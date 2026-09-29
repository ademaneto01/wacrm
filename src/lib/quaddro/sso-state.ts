// ============================================================
// Login-CSRF protection for the Quaddro SSO callback.
//
// /api/sso/quaddro/start drops a random `state` in an HttpOnly cookie
// scoped to /api/sso/quaddro and sends the browser to Quaddro, which
// signs that same state into the handoff token. The callback accepts a
// token only when its `state` claim matches THIS browser's cookie — so
// an attacker cannot push their own (validly signed) token at a
// victim's browser and sign the victim into the attacker's workspace.
//
// The cookie also remembers where the user was headed (`next`), so a
// deep link that bounced through SSO lands back where it started.
// ============================================================

import { randomBytes, timingSafeEqual } from 'node:crypto'
import { safeNextPath } from '@/lib/auth/callback'

export const STATE_COOKIE = 'wacrm_quaddro_sso'
export const STATE_COOKIE_PATH = '/api/sso/quaddro'
/** How long the user has to get through Quaddro and back. */
export const STATE_TTL_S = 300

export function newState(): string {
  return randomBytes(32).toString('base64url')
}

export function encodeStateCookie(state: string, next: string): string {
  return `${state}~${encodeURIComponent(next)}`
}

export function decodeStateCookie(
  raw: string | undefined | null,
  fallbackNext: string,
): { state: string; next: string } | null {
  if (!raw) return null
  const sep = raw.indexOf('~')
  if (sep <= 0) return null
  const state = raw.slice(0, sep)
  let next: string
  try {
    next = decodeURIComponent(raw.slice(sep + 1))
  } catch {
    return null
  }
  return { state, next: safeNextPath(next, fallbackNext) }
}

export function statesMatch(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && timingSafeEqual(left, right)
}

/**
 * Cookie attributes. Over HTTPS the cookie is `SameSite=None; Secure`
 * because the callback is a cross-site POST whenever Quaddro and this
 * app live on different registrable domains (Lax cookies are not sent
 * on cross-site POSTs). On plain-HTTP localhost both apps are the same
 * site, so Lax works and Secure would be refused.
 */
export function stateCookieOptions(secure: boolean) {
  return {
    httpOnly: true,
    secure,
    sameSite: secure ? ('none' as const) : ('lax' as const),
    path: STATE_COOKIE_PATH,
    maxAge: STATE_TTL_S,
  }
}

/** Whether the browser reached us over HTTPS (directly or via a proxy). */
export function isSecureRequest(request: Request): boolean {
  const forwarded = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim()
  if (forwarded) return forwarded === 'https'
  return new URL(request.url).protocol === 'https:'
}
