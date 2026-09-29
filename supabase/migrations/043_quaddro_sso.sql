-- ============================================================
-- 043_quaddro_sso
--
-- Single sign-on from the Quaddro panel (web-pro-app). A Quaddro user
-- clicks "WhatsApp" in the Quaddro sidebar and lands here already
-- signed in, inside the workspace of the Quaddro business they have
-- selected. No password, no signup. See src/lib/quaddro/.
--
-- Identity mapping — Quaddro is the source of truth:
--
--   Quaddro business id  ──1:1──  accounts row        (quaddro_business_links)
--   (business id, member id) ──1:1── auth.users row   (quaddro_member_links)
--
-- A Quaddro member can belong to several businesses, while a WACRM
-- user belongs to exactly one account (profiles.account_id, 017). So
-- the WACRM user is keyed by the (business, member) PAIR: the same
-- person opening two different businesses gets two WACRM users, one
-- per workspace, and the two can never see each other's data. That
-- keeps the existing RLS model (is_account_member) untouched.
--
-- Every business account is owned by a dedicated, login-disabled
-- "system owner" user (created by the app with a ban), so no real
-- person holds the owner-only powers by accident of who opened the
-- integration first. Real people get admin/agent/viewer from their
-- Quaddro role, re-synced on every sign-in.
--
-- Replay protection: every handoff token carries a unique `jti`; it is
-- inserted into quaddro_sso_nonces on use and a second insert of the
-- same id is rejected by the primary key.
--
-- All three tables are service-role only: RLS on, no policies, and
-- no grants to anon/authenticated. Browser clients never read them.
--
-- Idempotent — safe to re-run.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.quaddro_business_links (
  quaddro_business_id TEXT PRIMARY KEY
    CHECK (char_length(quaddro_business_id) BETWEEN 1 AND 128),
  account_id UUID NOT NULL UNIQUE REFERENCES public.accounts(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.quaddro_member_links (
  quaddro_business_id TEXT NOT NULL
    CHECK (char_length(quaddro_business_id) BETWEEN 1 AND 128),
  quaddro_member_id TEXT NOT NULL
    CHECK (char_length(quaddro_member_id) BETWEEN 1 AND 128),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_sign_in_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (quaddro_business_id, quaddro_member_id)
);

CREATE TABLE IF NOT EXISTS public.quaddro_sso_nonces (
  jti TEXT PRIMARY KEY CHECK (char_length(jti) BETWEEN 16 AND 128),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quaddro_sso_nonces_expires_at
  ON public.quaddro_sso_nonces(expires_at);

ALTER TABLE public.quaddro_business_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quaddro_member_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quaddro_sso_nonces ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.quaddro_business_links FROM anon, authenticated;
REVOKE ALL ON public.quaddro_member_links FROM anon, authenticated;
REVOKE ALL ON public.quaddro_sso_nonces FROM anon, authenticated;

-- ------------------------------------------------------------
-- quaddro_consume_sso_nonce(jti, expires_at) → boolean
--
-- TRUE the first time a jti is presented, FALSE on any replay.
-- Also sweeps expired rows so the table stays tiny (a token is only
-- valid for ~1 minute, so anything past expiry can never be replayed
-- successfully anyway — the signature check rejects it first).
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.quaddro_consume_sso_nonce(
  p_jti TEXT,
  p_expires_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_inserted INTEGER;
BEGIN
  DELETE FROM quaddro_sso_nonces WHERE expires_at < NOW() - INTERVAL '1 hour';

  INSERT INTO quaddro_sso_nonces (jti, expires_at)
  VALUES (p_jti, p_expires_at)
  ON CONFLICT (jti) DO NOTHING;

  GET DIAGNOSTICS v_inserted = ROW_COUNT;
  RETURN v_inserted = 1;
END;
$$;

ALTER FUNCTION public.quaddro_consume_sso_nonce(TEXT, TIMESTAMPTZ) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.quaddro_consume_sso_nonce(TEXT, TIMESTAMPTZ) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.quaddro_consume_sso_nonce(TEXT, TIMESTAMPTZ) TO service_role;

-- ------------------------------------------------------------
-- quaddro_auth_user_id(email) → uuid
--
-- Looks up an auth user by (synthetic) email. supabase-js has no
-- "get user by email" admin call, and the app needs one to recover
-- from the race where two first-time sign-ins create the same user.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.quaddro_auth_user_id(p_email TEXT)
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT id FROM auth.users WHERE email = lower(p_email) LIMIT 1;
$$;

ALTER FUNCTION public.quaddro_auth_user_id(TEXT) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.quaddro_auth_user_id(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.quaddro_auth_user_id(TEXT) TO service_role;

-- ------------------------------------------------------------
-- quaddro_provision_member(...) → account id
--
-- Called by the SSO callback after both auth users exist (the
-- business's system owner and the signing-in member). In ONE
-- transaction, serialised per Quaddro business by an advisory lock:
--
--   1. Resolve the business's account. First time: adopt the system
--      owner's personal account (created by the 017 signup trigger),
--      rename it to the Quaddro business name and link it. Later:
--      re-sync the name if it changed in Quaddro.
--   2. Put the member's profile in that account with the mapped role.
--      A brand-new member still sits in their own trigger-created
--      personal account — move them (profile first, so the cascade
--      doesn't take the profile with it) and delete the empty
--      personal account, exactly like redeem_invitation (019).
--   3. Upsert the (business, member) → user link.
--
-- Every step is a no-op when the state is already right, so calling
-- it on every sign-in is safe: no duplicate accounts, users,
-- memberships or links.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.quaddro_provision_member(
  p_business_id TEXT,
  p_business_name TEXT,
  p_owner_user_id UUID,
  p_member_id TEXT,
  p_user_id UUID,
  p_role account_role_enum,
  p_full_name TEXT,
  p_email TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_account_id UUID;
  v_owner_account_id UUID;
  v_profile_account_id UUID;
  v_profile_role account_role_enum;
  v_old_owner UUID;
  v_name TEXT := left(btrim(coalesce(p_business_name, '')), 200);
BEGIN
  IF p_role = 'owner' THEN
    RAISE EXCEPTION 'owner is reserved for the business system user'
      USING ERRCODE = '22023';
  END IF;
  IF p_owner_user_id = p_user_id THEN
    RAISE EXCEPTION 'member and system owner must be different users'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('quaddro_business:' || p_business_id, 0));

  -- 1. The business's account.
  SELECT account_id INTO v_account_id
  FROM quaddro_business_links
  WHERE quaddro_business_id = p_business_id;

  IF v_account_id IS NULL THEN
    SELECT p.account_id INTO v_owner_account_id
    FROM profiles p
    JOIN accounts a ON a.id = p.account_id
    WHERE p.user_id = p_owner_user_id
      AND a.owner_user_id = p_owner_user_id;

    IF v_owner_account_id IS NULL THEN
      -- The 017 trigger swallows its own errors; surface it here.
      RAISE EXCEPTION 'system owner % has no personal account', p_owner_user_id
        USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO quaddro_business_links (quaddro_business_id, account_id)
    VALUES (p_business_id, v_owner_account_id);
    v_account_id := v_owner_account_id;
  END IF;

  IF v_name <> '' THEN
    UPDATE accounts SET name = v_name, updated_at = NOW()
    WHERE id = v_account_id AND name IS DISTINCT FROM v_name;
    UPDATE quaddro_business_links SET updated_at = NOW()
    WHERE quaddro_business_id = p_business_id;
  END IF;

  -- 2. The member's membership.
  SELECT account_id, account_role INTO v_profile_account_id, v_profile_role
  FROM profiles WHERE user_id = p_user_id;

  IF v_profile_account_id IS NULL THEN
    RAISE EXCEPTION 'user % has no profile', p_user_id USING ERRCODE = 'P0002';
  END IF;

  IF v_profile_account_id <> v_account_id THEN
    SELECT owner_user_id INTO v_old_owner FROM accounts WHERE id = v_profile_account_id;

    UPDATE profiles
    SET account_id = v_account_id,
        account_role = p_role,
        full_name = coalesce(nullif(btrim(p_full_name), ''), full_name),
        email = coalesce(nullif(btrim(p_email), ''), email),
        updated_at = NOW()
    WHERE user_id = p_user_id;

    -- Only ever delete the member's own, now-empty personal account.
    IF v_old_owner = p_user_id AND NOT EXISTS (
      SELECT 1 FROM profiles WHERE account_id = v_profile_account_id
    ) THEN
      DELETE FROM accounts WHERE id = v_profile_account_id;
    END IF;
  ELSE
    UPDATE profiles
    SET account_role = CASE WHEN v_profile_role = 'owner' THEN v_profile_role ELSE p_role END,
        full_name = coalesce(nullif(btrim(p_full_name), ''), full_name),
        email = coalesce(nullif(btrim(p_email), ''), email),
        updated_at = NOW()
    WHERE user_id = p_user_id
      AND (
        (v_profile_role <> 'owner' AND account_role IS DISTINCT FROM p_role)
        OR full_name IS DISTINCT FROM coalesce(nullif(btrim(p_full_name), ''), full_name)
        OR email IS DISTINCT FROM coalesce(nullif(btrim(p_email), ''), email)
      );
  END IF;

  -- 3. The link.
  INSERT INTO quaddro_member_links (quaddro_business_id, quaddro_member_id, user_id)
  VALUES (p_business_id, p_member_id, p_user_id)
  ON CONFLICT (quaddro_business_id, quaddro_member_id)
  DO UPDATE SET last_sign_in_at = NOW()
  WHERE quaddro_member_links.user_id = EXCLUDED.user_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'member link for % already points at another user', p_member_id
      USING ERRCODE = '23505';
  END IF;

  RETURN v_account_id;
END;
$$;

ALTER FUNCTION public.quaddro_provision_member(TEXT, TEXT, UUID, TEXT, UUID, account_role_enum, TEXT, TEXT) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.quaddro_provision_member(TEXT, TEXT, UUID, TEXT, UUID, account_role_enum, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.quaddro_provision_member(TEXT, TEXT, UUID, TEXT, UUID, account_role_enum, TEXT, TEXT) TO service_role;
