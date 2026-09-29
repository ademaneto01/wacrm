-- ============================================================
-- 044_quaddro_patients
--
-- In Quaddro mode the contact list IS the business's patient list.
-- Quaddro stays the source of truth (clients + clients_businesses in
-- the Quaddro database); this migration lets WACRM mirror it into
-- `contacts` without touching the rest of the CRM:
--
--   * contacts.quaddro_client_id — the Quaddro `clients.id` a contact
--     mirrors. NULL = a plain WACRM contact (e.g. someone who messaged
--     the business but is not a patient). Unique per account.
--   * quaddro_sync_patients(account, patients) — service-role RPC the
--     app calls with the list fetched from the Quaddro API. Links,
--     updates, inserts and unlinks in one transaction.
--   * a guard trigger that keeps name / phone of a linked contact and
--     the link itself read-only for everyone but that RPC, so the
--     webhook (WhatsApp profile name), automations, the public API and
--     the UI cannot drift from Quaddro.
--
-- Contacts are never deleted by the sync: deleting a contact cascades
-- to its conversations and messages (001). A patient archived in
-- Quaddro is only unlinked — the chat history stays in the inbox.
--
-- Tenant isolation is unchanged: every row still carries account_id
-- and the existing RLS (017) scopes reads to the caller's account.
--
-- Idempotent — safe to re-run.
-- ============================================================

ALTER TABLE public.contacts
  ADD COLUMN IF NOT EXISTS quaddro_client_id TEXT
    CHECK (quaddro_client_id IS NULL OR char_length(quaddro_client_id) BETWEEN 1 AND 128);

CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_account_quaddro_client
  ON public.contacts (account_id, quaddro_client_id)
  WHERE quaddro_client_id IS NOT NULL;

ALTER TABLE public.quaddro_business_links
  ADD COLUMN IF NOT EXISTS patients_synced_at TIMESTAMPTZ;

-- ------------------------------------------------------------
-- Guard: fields owned by Quaddro are read-only outside the sync.
--
-- Silently keeps the old values instead of raising, so a WhatsApp
-- delivery that would rename the contact to its profile name, or an
-- automation that sets the name, still goes through for every other
-- column. A phone rewrite that keeps the same last 8 digits (the
-- send path's trunk-0 / BR 9th-digit auto-correct, see phonesMatch)
-- is allowed — it is the same number, spelled the way Meta accepts.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.contacts_guard_quaddro_fields()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF current_setting('wacrm.quaddro_sync', true) = 'on' THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.quaddro_client_id := NULL;
    RETURN NEW;
  END IF;

  NEW.quaddro_client_id := OLD.quaddro_client_id;

  IF OLD.quaddro_client_id IS NOT NULL THEN
    NEW.name := OLD.name;
    IF right(regexp_replace(coalesce(NEW.phone, ''), '\D', '', 'g'), 8)
       IS DISTINCT FROM right(coalesce(OLD.phone_normalized, ''), 8) THEN
      NEW.phone := OLD.phone;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS contacts_guard_quaddro_fields ON public.contacts;
CREATE TRIGGER contacts_guard_quaddro_fields
  BEFORE INSERT OR UPDATE ON public.contacts
  FOR EACH ROW EXECUTE FUNCTION public.contacts_guard_quaddro_fields();

-- ------------------------------------------------------------
-- quaddro_sync_patients(account_id, patients jsonb) → jsonb counts
--
-- `patients` is the full, current list for the account's business:
-- [{ "id": "<clients.id>", "name": "...", "phone": "5511999999999" }].
-- Entries without a usable phone (8–15 digits) are ignored: they
-- cannot be reached on WhatsApp.
--
--   1. unlink contacts whose patient is no longer in the list;
--   2. adopt existing unlinked contacts with the same number (last 8
--      digits, exact match preferred) — e.g. someone who messaged
--      first and was registered as a patient afterwards;
--   3. refresh name / phone of linked contacts;
--   4. insert the remaining patients as new contacts.
--
-- Serialized per account with an advisory lock; sets the session flag
-- the guard trigger honours for this transaction only.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.quaddro_sync_patients(
  p_account_id UUID,
  p_patients JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_audit_user UUID;
  v_unlinked INT := 0;
  v_linked INT := 0;
  v_renamed INT := 0;
  v_rephoned INT := 0;
  v_inserted INT := 0;
  v_total INT := 0;
  v_row RECORD;
BEGIN
  IF p_patients IS NULL OR jsonb_typeof(p_patients) <> 'array' THEN
    RAISE EXCEPTION 'p_patients must be a JSON array';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('quaddro_sync_patients:' || p_account_id::text, 0));
  PERFORM set_config('wacrm.quaddro_sync', 'on', true);

  -- contacts.user_id is NOT NULL (audit column). The account owner is
  -- the login-disabled Quaddro system user (043).
  SELECT owner_user_id INTO v_audit_user FROM accounts WHERE id = p_account_id;
  IF v_audit_user IS NULL THEN
    RAISE EXCEPTION 'account % not found', p_account_id;
  END IF;

  CREATE TEMP TABLE quaddro_incoming ON COMMIT DROP AS
  SELECT DISTINCT ON (x.id)
    x.id,
    left(btrim(coalesce(x.name, '')), 200) AS name,
    regexp_replace(coalesce(x.phone, ''), '\D', '', 'g') AS phone
  FROM jsonb_to_recordset(p_patients) AS x(id TEXT, name TEXT, phone TEXT)
  WHERE x.id ~ '^[A-Za-z0-9_-]{1,128}$'
    AND regexp_replace(coalesce(x.phone, ''), '\D', '', 'g') ~ '^[1-9][0-9]{7,14}$'
  ORDER BY x.id;

  SELECT count(*) INTO v_total FROM pg_temp.quaddro_incoming;

  -- 1. unlink
  UPDATE contacts c
     SET quaddro_client_id = NULL, updated_at = NOW()
   WHERE c.account_id = p_account_id
     AND c.quaddro_client_id IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_temp.quaddro_incoming i WHERE i.id = c.quaddro_client_id);
  GET DIAGNOSTICS v_unlinked = ROW_COUNT;

  -- 2. adopt by phone (one patient per contact, one contact per patient)
  WITH candidates AS (
    SELECT i.id AS patient_id, c.id AS contact_id,
           (c.phone_normalized = i.phone) AS exact, c.created_at
      FROM pg_temp.quaddro_incoming i
      JOIN contacts c
        ON c.account_id = p_account_id
       AND c.quaddro_client_id IS NULL
       AND length(c.phone_normalized) >= 8
       AND right(c.phone_normalized, 8) = right(i.phone, 8)
     WHERE NOT EXISTS (
       SELECT 1 FROM contacts l
        WHERE l.account_id = p_account_id AND l.quaddro_client_id = i.id
     )
  ),
  per_patient AS (
    SELECT DISTINCT ON (patient_id) patient_id, contact_id, exact
      FROM candidates
     ORDER BY patient_id, exact DESC, created_at ASC, contact_id
  ),
  per_contact AS (
    SELECT DISTINCT ON (contact_id) patient_id, contact_id
      FROM per_patient
     ORDER BY contact_id, exact DESC, patient_id
  )
  UPDATE contacts c
     SET quaddro_client_id = pc.patient_id, updated_at = NOW()
    FROM per_contact pc
   WHERE c.id = pc.contact_id;
  GET DIAGNOSTICS v_linked = ROW_COUNT;

  -- 3a. names (an empty Quaddro name never blanks an existing one)
  UPDATE contacts c
     SET name = i.name, updated_at = NOW()
    FROM pg_temp.quaddro_incoming i
   WHERE c.account_id = p_account_id
     AND c.quaddro_client_id = i.id
     AND i.name <> ''
     AND c.name IS DISTINCT FROM i.name;
  GET DIAGNOSTICS v_renamed = ROW_COUNT;

  -- 3b. numbers — only a real change of number (last 8 digits differ),
  -- so the send path's variant auto-correct is not undone. Row by row:
  -- the new number may already belong to another contact.
  FOR v_row IN
    SELECT c.id, i.phone
      FROM contacts c
      JOIN pg_temp.quaddro_incoming i ON i.id = c.quaddro_client_id
     WHERE c.account_id = p_account_id
       AND right(c.phone_normalized, 8) IS DISTINCT FROM right(i.phone, 8)
  LOOP
    BEGIN
      UPDATE contacts SET phone = v_row.phone, updated_at = NOW() WHERE id = v_row.id;
      v_rephoned := v_rephoned + 1;
    EXCEPTION WHEN unique_violation THEN
      NULL;
    END;
  END LOOP;

  -- 4. insert the rest; ON CONFLICT covers a number already taken by a
  -- contact linked to another patient (and any concurrent writer).
  INSERT INTO contacts (account_id, user_id, phone, name, quaddro_client_id)
  SELECT p_account_id, v_audit_user, i.phone, NULLIF(i.name, ''), i.id
    FROM pg_temp.quaddro_incoming i
   WHERE NOT EXISTS (
     SELECT 1 FROM contacts c
      WHERE c.account_id = p_account_id AND c.quaddro_client_id = i.id
   )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_inserted = ROW_COUNT;

  UPDATE quaddro_business_links
     SET patients_synced_at = NOW(), updated_at = NOW()
   WHERE account_id = p_account_id;

  -- Close the bypass now rather than at commit, so any later statement
  -- in the caller's transaction is guarded again.
  DROP TABLE pg_temp.quaddro_incoming;
  PERFORM set_config('wacrm.quaddro_sync', 'off', true);

  RETURN jsonb_build_object(
    'patients', v_total,
    'inserted', v_inserted,
    'linked', v_linked,
    'renamed', v_renamed,
    'rephoned', v_rephoned,
    'unlinked', v_unlinked
  );
END;
$$;

ALTER FUNCTION public.quaddro_sync_patients(UUID, JSONB) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.quaddro_sync_patients(UUID, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.quaddro_sync_patients(UUID, JSONB) TO service_role;

-- ------------------------------------------------------------
-- filter_contacts_by_tags (025) + p_quaddro_only
--
-- The contacts page lists only patients in Quaddro mode; the tag
-- filter path must honour the same restriction or it would page over
-- a different set. Same body as 025 plus one predicate; the new
-- parameter defaults to false so existing callers are unaffected.
-- ------------------------------------------------------------
DROP FUNCTION IF EXISTS public.filter_contacts_by_tags(UUID[], TEXT, INT, INT);

CREATE OR REPLACE FUNCTION public.filter_contacts_by_tags(
  p_tag_ids UUID[],
  p_search TEXT DEFAULT NULL,
  p_limit INT DEFAULT 25,
  p_offset INT DEFAULT 0,
  p_quaddro_only BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (contact contacts, total_count BIGINT)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  WITH matched AS (
    SELECT DISTINCT c.id, c.created_at
    FROM contacts c
    JOIN contact_tags ct ON ct.contact_id = c.id
    WHERE ct.tag_id = ANY(p_tag_ids)
      AND (NOT p_quaddro_only OR c.quaddro_client_id IS NOT NULL)
      AND (
        p_search IS NULL
        OR c.name ILIKE '%' || p_search || '%'
        OR c.phone ILIKE '%' || p_search || '%'
        OR c.email ILIKE '%' || p_search || '%'
      )
  ),
  page AS (
    SELECT id, count(*) OVER() AS total_count
    FROM matched
    ORDER BY created_at DESC, id
    LIMIT p_limit OFFSET p_offset
  )
  SELECT c AS contact, page.total_count
  FROM page
  JOIN contacts c ON c.id = page.id
  ORDER BY c.created_at DESC, c.id;
$$;

ALTER FUNCTION public.filter_contacts_by_tags(UUID[], TEXT, INT, INT, BOOLEAN) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.filter_contacts_by_tags(UUID[], TEXT, INT, INT, BOOLEAN) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.filter_contacts_by_tags(UUID[], TEXT, INT, INT, BOOLEAN) TO authenticated;
