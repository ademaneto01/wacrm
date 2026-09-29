// ============================================================
// Quaddro patients → WACRM contacts.
//
// In Quaddro mode the contact list is the business's patient list.
// Quaddro owns it (clients + clients_businesses); this module pulls
// the current list from the Quaddro API and mirrors it into
// `contacts` through the quaddro_sync_patients RPC (migration 044).
//
// Server-to-server only. The request is authorized by a 60-second
// HS256 token signed with QUADDRO_API_SECRET (the same value as
// WACRM_API_SECRET in Quaddro's apps/api) whose `sub` is the Quaddro
// business id. The business id is resolved here from the caller's
// account via quaddro_business_links — never taken from the browser —
// so a user can only ever sync (and see) their own business.
//
// Token contract (keep in sync with Quaddro
// shared/operations/src/infra/gateways/wacrmToken):
//   header {"alg":"HS256","typ":"JWT"}
//   iss "wacrm"  aud "quaddro"  scope "patients:read"
//   sub <business uuid>  iat/exp (60 s)  jti
// ============================================================

import { createHmac, randomUUID } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'
import { MIN_SECRET_LENGTH } from '@/lib/quaddro/sso-token'

export const PATIENTS_TOKEN_ISSUER = 'wacrm'
export const PATIENTS_TOKEN_AUDIENCE = 'quaddro'
export const PATIENTS_SCOPE = 'patients:read'
export const PATIENTS_TOKEN_LIFETIME_S = 60

/** Automatic syncs (page open, sign-in) run at most this often per account. */
export const AUTO_SYNC_INTERVAL_MS = 60_000
/** Even a manual "sync now" is spaced out by this much. */
export const FORCED_SYNC_INTERVAL_MS = 10_000

const LIST_PATIENTS_PATH = '/operations/integrations/wacrm/listPatients'
const REQUEST_TIMEOUT_MS = 20_000
/** Sanity cap on one business's patient list. */
const MAX_PATIENTS = 100_000

export interface QuaddroPatient {
  id: string
  name: string
  phone: string
}

export interface SyncCounts {
  patients: number
  inserted: number
  linked: number
  renamed: number
  rephoned: number
  unlinked: number
}

export type SyncOutcome =
  | { status: 'synced'; counts: SyncCounts }
  | { status: 'skipped'; reason: 'not_linked' | 'not_configured' | 'recent' }

export class QuaddroPatientsError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'QuaddroPatientsError'
  }
}

export interface PatientsApiConfig {
  /** Quaddro API origin (apps/api), no trailing slash. */
  apiUrl: string
  secret: string
}

/** Server-side config, or null when patient sync is not configured. */
export function getPatientsApiConfig(): PatientsApiConfig | null {
  const apiUrl = (process.env.QUADDRO_API_URL ?? '').trim().replace(/\/+$/, '')
  const secret = process.env.QUADDRO_API_SECRET ?? ''
  if (!apiUrl || secret.length < MIN_SECRET_LENGTH) return null
  return { apiUrl, secret }
}

function b64url(input: string | Buffer): string {
  return Buffer.from(input).toString('base64url')
}

export function signPatientsToken(
  businessId: string,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
  const header = { alg: 'HS256', typ: 'JWT' }
  const claims = {
    iss: PATIENTS_TOKEN_ISSUER,
    aud: PATIENTS_TOKEN_AUDIENCE,
    scope: PATIENTS_SCOPE,
    sub: businessId,
    iat: nowSeconds,
    exp: nowSeconds + PATIENTS_TOKEN_LIFETIME_S,
    jti: randomUUID(),
  }
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`
  const signature = createHmac('sha256', secret).update(signingInput).digest()
  return `${signingInput}.${b64url(signature)}`
}

/**
 * Parse the Quaddro operations response. Success bodies are superjson
 * (`{ json: { result } }`), errors to a JSON request are plain JSON
 * (`{ error }`) — both are accepted. Anything off-contract throws.
 */
export function parsePatientsResponse(body: unknown): QuaddroPatient[] {
  const envelope =
    body && typeof body === 'object' && 'json' in body
      ? (body as { json: unknown }).json
      : body
  if (!envelope || typeof envelope !== 'object') {
    throw new QuaddroPatientsError('unexpected response')
  }
  const { result, error } = envelope as {
    result?: { data?: unknown }
    error?: { code?: unknown }
  }
  if (error) throw new QuaddroPatientsError(`quaddro error ${String(error.code ?? '?')}`)

  const data = result?.data
  if (!Array.isArray(data)) throw new QuaddroPatientsError('unexpected response')
  if (data.length > MAX_PATIENTS) throw new QuaddroPatientsError('too many patients')

  const patients: QuaddroPatient[] = []
  for (const item of data) {
    if (!item || typeof item !== 'object') continue
    const { id, name, phone } = item as Record<string, unknown>
    if (typeof id !== 'string' || !id) continue
    patients.push({
      id,
      name: typeof name === 'string' ? name : '',
      phone: typeof phone === 'string' ? phone : '',
    })
  }
  return patients
}

export async function fetchQuaddroPatients(
  businessId: string,
  config: PatientsApiConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<QuaddroPatient[]> {
  const token = signPatientsToken(businessId, config.secret)
  let response: Response
  try {
    response = await fetchImpl(`${config.apiUrl}${LIST_PATIENTS_PATH}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { token } }),
      cache: 'no-store',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
  } catch {
    throw new QuaddroPatientsError('quaddro api unreachable')
  }
  if (!response.ok) throw new QuaddroPatientsError(`quaddro api http ${response.status}`)

  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new QuaddroPatientsError('unexpected response')
  }
  return parsePatientsResponse(body)
}

/** Whether a sync last stamped at `lastSyncedAt` may run again now. */
export function isSyncDue(
  lastSyncedAt: string | null | undefined,
  force: boolean,
  nowMs: number = Date.now(),
): boolean {
  if (!lastSyncedAt) return true
  const last = Date.parse(lastSyncedAt)
  if (Number.isNaN(last)) return true
  return nowMs - last >= (force ? FORCED_SYNC_INTERVAL_MS : AUTO_SYNC_INTERVAL_MS)
}

/**
 * Mirror the account's Quaddro patients into its contacts. `admin` must
 * be the service-role client: the link table and the RPC are closed to
 * browser roles. `accountId` must come from the caller's session.
 */
export async function syncQuaddroPatients(
  admin: SupabaseClient,
  accountId: string,
  { force = false, fetchImpl }: { force?: boolean; fetchImpl?: typeof fetch } = {},
): Promise<SyncOutcome> {
  const config = getPatientsApiConfig()
  if (!config) return { status: 'skipped', reason: 'not_configured' }

  const { data: link, error } = await admin
    .from('quaddro_business_links')
    .select('quaddro_business_id, patients_synced_at')
    .eq('account_id', accountId)
    .maybeSingle()
  if (error) throw new QuaddroPatientsError('link lookup failed')
  if (!link) return { status: 'skipped', reason: 'not_linked' }
  if (!isSyncDue(link.patients_synced_at, force)) return { status: 'skipped', reason: 'recent' }

  const patients = await fetchQuaddroPatients(link.quaddro_business_id, config, fetchImpl)

  const { data: counts, error: rpcError } = await admin.rpc('quaddro_sync_patients', {
    p_account_id: accountId,
    p_patients: patients,
  })
  if (rpcError || !counts) throw new QuaddroPatientsError('sync rpc failed')
  return { status: 'synced', counts: counts as SyncCounts }
}
