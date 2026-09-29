// ============================================================
// Quaddro → WACRM handoff token.
//
// A compact JWS (JWT) signed with HS256 by the Quaddro panel's server
// (web-pro-app, app/utils/wacrm.server.ts) using a secret shared only
// between the two servers (QUADDRO_SSO_SECRET here, WACRM_SSO_SECRET
// there). It never touches the browser in a URL: Quaddro renders it
// into an auto-submitting POST form aimed at /api/sso/quaddro/callback.
//
// Contract (keep in sync with the Quaddro side):
//   header  {"alg":"HS256","typ":"JWT"}
//   iss     "quaddro"            aud  "wacrm"
//   iat/exp seconds; exp - iat ≤ MAX_LIFETIME_S (Quaddro issues 60 s)
//   jti     unique id, single use (quaddro_sso_nonces)
//   state   echo of the state cookie set by /api/sso/quaddro/start
//   sub     Quaddro member id     bid   Quaddro business id
//   bname   business display name name / email  member display data
//   role    Quaddro role: owner | admin | assistant | employee
//
// Hand-rolled on node:crypto on purpose: one algorithm, one key, no
// `alg` negotiation (the classic JWT pitfall), no new dependency.
// ============================================================

import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AccountRole } from '@/lib/auth/roles'

export const SSO_ISSUER = 'quaddro'
export const SSO_AUDIENCE = 'wacrm'
/** Longest lifetime accepted, whatever the token claims. */
export const MAX_LIFETIME_S = 120
/** Tolerated clock drift between the two servers. */
export const CLOCK_SKEW_S = 30
/** Minimum shared-secret length (bytes of the UTF-8 string). */
export const MIN_SECRET_LENGTH = 32

export const QUADDRO_ROLES = ['owner', 'admin', 'assistant', 'employee'] as const
export type QuaddroRole = (typeof QUADDRO_ROLES)[number]

export interface QuaddroSsoClaims {
  iss: typeof SSO_ISSUER
  aud: typeof SSO_AUDIENCE
  iat: number
  exp: number
  jti: string
  state: string
  sub: string
  bid: string
  bname: string
  name: string
  email: string
  role: QuaddroRole
}

export type SsoTokenError =
  | 'malformed'
  | 'bad_signature'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'lifetime_too_long'
  | 'invalid_claims'

export type VerifyResult =
  | { ok: true; claims: QuaddroSsoClaims }
  | { ok: false; error: SsoTokenError }

const HEADER = { alg: 'HS256', typ: 'JWT' } as const

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

function hmac(secret: string, data: string): Buffer {
  return createHmac('sha256', secret).update(data).digest()
}

/**
 * The server-side shared secret, or null when the integration is not
 * configured (or configured with a secret too short to be safe).
 */
export function getSsoSecret(): string | null {
  const secret = process.env.QUADDRO_SSO_SECRET ?? ''
  return secret.length >= MIN_SECRET_LENGTH ? secret : null
}

/** Sign a token. Production tokens are signed by Quaddro; this exists for tests and local tooling. */
export function signSsoToken(claims: QuaddroSsoClaims, secret: string): string {
  const signingInput = `${b64url(JSON.stringify(HEADER))}.${b64url(JSON.stringify(claims))}`
  return `${signingInput}.${b64url(hmac(secret, signingInput))}`
}

const ID_RE = /^[A-Za-z0-9_-]{1,128}$/
const JTI_RE = /^[A-Za-z0-9_-]{16,128}$/
const STATE_RE = /^[A-Za-z0-9_-]{32,128}$/

function isNonEmptyString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= max
}

function validClaims(c: Record<string, unknown>): c is QuaddroSsoClaims & Record<string, unknown> {
  return (
    Number.isInteger(c.iat) &&
    Number.isInteger(c.exp) &&
    typeof c.jti === 'string' && JTI_RE.test(c.jti) &&
    typeof c.state === 'string' && STATE_RE.test(c.state) &&
    typeof c.sub === 'string' && ID_RE.test(c.sub) &&
    typeof c.bid === 'string' && ID_RE.test(c.bid) &&
    isNonEmptyString(c.bname, 200) &&
    isNonEmptyString(c.name, 200) &&
    typeof c.email === 'string' && c.email.length <= 320 &&
    typeof c.role === 'string' && (QUADDRO_ROLES as readonly string[]).includes(c.role)
  )
}

/**
 * Verify signature, issuer, audience, time window and claim shapes.
 * Replay (jti reuse) and state binding are checked by the caller —
 * they need the database and the request cookie respectively.
 */
export function verifySsoToken(
  token: string,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): VerifyResult {
  if (typeof token !== 'string' || token.length > 8192) return { ok: false, error: 'malformed' }
  const parts = token.split('.')
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    return { ok: false, error: 'malformed' }
  }
  const [headerPart, payloadPart, signaturePart] = parts

  let header: unknown
  let payload: unknown
  try {
    header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8'))
    payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'))
  } catch {
    return { ok: false, error: 'malformed' }
  }
  if (
    !header || typeof header !== 'object' ||
    (header as Record<string, unknown>).alg !== 'HS256' ||
    !payload || typeof payload !== 'object' || Array.isArray(payload)
  ) {
    return { ok: false, error: 'malformed' }
  }

  // Signature before any claim is trusted.
  const expected = hmac(secret, `${headerPart}.${payloadPart}`)
  const given = Buffer.from(signaturePart, 'base64url')
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return { ok: false, error: 'bad_signature' }
  }

  const claims = payload as Record<string, unknown>
  if (claims.iss !== SSO_ISSUER) return { ok: false, error: 'wrong_issuer' }
  if (claims.aud !== SSO_AUDIENCE) return { ok: false, error: 'wrong_audience' }
  if (!validClaims(claims)) return { ok: false, error: 'invalid_claims' }

  if (claims.exp - claims.iat > MAX_LIFETIME_S) return { ok: false, error: 'lifetime_too_long' }
  if (claims.iat > nowSeconds + CLOCK_SKEW_S) return { ok: false, error: 'not_yet_valid' }
  if (claims.exp <= nowSeconds - CLOCK_SKEW_S) return { ok: false, error: 'expired' }

  return {
    ok: true,
    claims: {
      iss: SSO_ISSUER,
      aud: SSO_AUDIENCE,
      iat: claims.iat,
      exp: claims.exp,
      jti: claims.jti,
      state: claims.state,
      sub: claims.sub,
      bid: claims.bid,
      bname: claims.bname.trim(),
      name: claims.name.trim(),
      email: claims.email.trim(),
      role: claims.role,
    },
  }
}

/**
 * Quaddro role → WACRM role. `owner` in WACRM is reserved for the
 * business's system user (migration 043), so Quaddro owners and admins
 * both become WACRM admins; assistants and employees work the inbox.
 */
export function mapQuaddroRole(role: QuaddroRole): Exclude<AccountRole, 'owner'> {
  switch (role) {
    case 'owner':
    case 'admin':
      return 'admin'
    case 'assistant':
    case 'employee':
      return 'agent'
  }
}
