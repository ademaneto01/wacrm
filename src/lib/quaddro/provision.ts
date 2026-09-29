// ============================================================
// Just-in-time provisioning for Quaddro SSO sign-ins.
//
// On every sign-in (idempotent — the second, tenth and hundredth call
// change nothing unless Quaddro data changed):
//
//   1. ensure the business's system owner user exists (login-disabled);
//   2. ensure the member's user exists, keyed by (business, member);
//   3. quaddro_provision_member (migration 043) links/renames the
//      business account and puts the member in it with the mapped role.
//
// Auth users get a deterministic synthetic email derived from the
// Quaddro ids. It is never mailed (we mint sessions with admin
// generateLink + verifyOtp, no email is sent) and it makes user
// creation naturally idempotent: two concurrent first sign-ins race on
// the same email, one wins, the other looks the winner up.
// The member's real name/email are kept on `profiles` for display.
// ============================================================

import { createHash } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'
import { mapQuaddroRole, type QuaddroSsoClaims } from './sso-token'

/** RFC 2606 reserved TLD: can never be a real, deliverable mailbox. */
export const SYNTHETIC_EMAIL_DOMAIN = 'sso.quaddro.invalid'

/** ~100 years. The system owner must never be able to sign in. */
const SYSTEM_OWNER_BAN = '876000h'

export function syntheticEmail(
  kind: 'owner' | 'member',
  businessId: string,
  memberId = '',
): string {
  const digest = createHash('sha256')
    .update(`quaddro:${kind}:${businessId}:${memberId}`)
    .digest('hex')
    .slice(0, 40)
  return `${kind === 'owner' ? 'owner' : 'member'}-${digest}@${SYNTHETIC_EMAIL_DOMAIN}`
}

export class ProvisioningError extends Error {
  constructor(step: string, cause?: unknown) {
    super(`Quaddro provisioning failed at ${step}`)
    this.name = 'ProvisioningError'
    this.cause = cause
  }
}

async function findUserId(admin: SupabaseClient, email: string): Promise<string | null> {
  const { data, error } = await admin.rpc('quaddro_auth_user_id', { p_email: email })
  if (error) throw new ProvisioningError('user lookup', error)
  return typeof data === 'string' ? data : null
}

async function ensureAuthUser(
  admin: SupabaseClient,
  email: string,
  metadata: Record<string, unknown>,
  { systemOwner = false }: { systemOwner?: boolean } = {},
): Promise<string> {
  const existing = await findUserId(admin, email)
  if (existing) return existing

  const { data, error } = await admin.auth.admin.createUser({
    email,
    email_confirm: true,
    user_metadata: metadata,
    ...(systemOwner ? { ban_duration: SYSTEM_OWNER_BAN } : {}),
  })
  if (data?.user?.id) return data.user.id

  // Lost a race with a concurrent first sign-in for the same identity.
  const raced = await findUserId(admin, email)
  if (raced) return raced
  throw new ProvisioningError(systemOwner ? 'create system owner' : 'create member', error)
}

export interface ProvisionedMember {
  userId: string
  accountId: string
  /** Synthetic auth email — what a session is minted for. */
  authEmail: string
}

export async function provisionQuaddroMember(
  admin: SupabaseClient,
  claims: QuaddroSsoClaims,
): Promise<ProvisionedMember> {
  const ownerId = await ensureAuthUser(
    admin,
    syntheticEmail('owner', claims.bid),
    { full_name: 'Quaddro', quaddro_business_id: claims.bid, quaddro_system_owner: true },
    { systemOwner: true },
  )

  const authEmail = syntheticEmail('member', claims.bid, claims.sub)
  const userId = await ensureAuthUser(admin, authEmail, {
    full_name: claims.name,
    quaddro_business_id: claims.bid,
    quaddro_member_id: claims.sub,
  })

  const { data: accountId, error } = await admin.rpc('quaddro_provision_member', {
    p_business_id: claims.bid,
    p_business_name: claims.bname,
    p_owner_user_id: ownerId,
    p_member_id: claims.sub,
    p_user_id: userId,
    p_role: mapQuaddroRole(claims.role),
    p_full_name: claims.name,
    p_email: claims.email,
  })
  if (error || typeof accountId !== 'string') {
    throw new ProvisioningError('membership', error)
  }

  return { userId, accountId, authEmail }
}

/** TRUE the first time a token id is seen, FALSE on replay. */
export async function consumeSsoNonce(
  admin: SupabaseClient,
  jti: string,
  expSeconds: number,
): Promise<boolean> {
  const { data, error } = await admin.rpc('quaddro_consume_sso_nonce', {
    p_jti: jti,
    p_expires_at: new Date(expSeconds * 1000).toISOString(),
  })
  if (error) throw new ProvisioningError('nonce', error)
  return data === true
}

/**
 * A one-time token hash for the member's auth user. Exchanged right
 * away with verifyOtp on the request's cookie-bound client, which is
 * what writes the Supabase session cookies. Nothing is emailed.
 */
export async function mintSessionTokenHash(
  admin: SupabaseClient,
  authEmail: string,
): Promise<string> {
  const { data, error } = await admin.auth.admin.generateLink({
    type: 'magiclink',
    email: authEmail,
  })
  const hash = data?.properties?.hashed_token
  if (error || !hash) throw new ProvisioningError('session link', error)
  return hash
}

/** Whether the account already has a connected WhatsApp number. */
export async function hasConnectedWhatsApp(
  admin: SupabaseClient,
  accountId: string,
): Promise<boolean> {
  const { data } = await admin
    .from('whatsapp_config')
    .select('status')
    .eq('account_id', accountId)
    .maybeSingle()
  return data?.status === 'connected'
}
