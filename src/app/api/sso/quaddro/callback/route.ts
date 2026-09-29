// ============================================================
// POST /api/sso/quaddro/callback   (form field: token)
//
// Last hop of the Quaddro SSO. The Quaddro panel auto-submits a form
// here carrying a 60-second HS256 handoff token (see
// src/lib/quaddro/sso-token.ts for the contract). In order:
//
//   1. signature / issuer / audience / expiry / claim shapes;
//   2. `state` claim == this browser's state cookie (login CSRF);
//   3. `jti` never seen before (replay);
//   4. provision business account + member user + membership;
//   5. mint a Supabase session on this response's cookies;
//   6. 303 to the inbox (or the WhatsApp connect screen);
//   7. after the response: refresh the business's patient list into
//      contacts (src/lib/quaddro/patients.ts) — never delays sign-in.
//
// Any failure lands on /sso/quaddro/error with a reason, never on a
// password form. Logs carry the reason only — no token, no PII.
// ============================================================

import { cookies } from 'next/headers'
import { after } from 'next/server'
import { relativeRedirect } from '@/lib/auth/callback'
import { isQuaddroMode } from '@/lib/quaddro/config'
import { getSsoSecret, verifySsoToken } from '@/lib/quaddro/sso-token'
import {
  STATE_COOKIE,
  decodeStateCookie,
  isSecureRequest,
  stateCookieOptions,
  statesMatch,
} from '@/lib/quaddro/sso-state'
import {
  consumeSsoNonce,
  hasConnectedWhatsApp,
  mintSessionTokenHash,
  provisionQuaddroMember,
} from '@/lib/quaddro/provision'
import { syncQuaddroPatients } from '@/lib/quaddro/patients'
import { DEFAULT_LANDING, landingPath, ssoFailure, type SsoFailure } from '@/lib/quaddro/sso-flow'
import { createClient } from '@/lib/supabase/server'
import { supabaseAdmin } from '@/lib/supabase/admin'

export const dynamic = 'force-dynamic'

function reject(reason: SsoFailure, detail?: string): Response {
  console.warn('[quaddro-sso] sign-in rejected:', { reason, detail })
  return ssoFailure(reason)
}

export async function POST(request: Request) {
  const secret = getSsoSecret()
  if (!isQuaddroMode() || !secret) return reject('not_configured')

  const cookieStore = await cookies()
  const saved = decodeStateCookie(cookieStore.get(STATE_COOKIE)?.value, DEFAULT_LANDING)
  // The state is single-use whatever happens next.
  cookieStore.set(STATE_COOKIE, '', { ...stateCookieOptions(isSecureRequest(request)), maxAge: 0 })

  let token: string | null = null
  try {
    const value = (await request.formData()).get('token')
    token = typeof value === 'string' ? value : null
  } catch {
    token = null
  }
  if (!token) return reject('invalid', 'missing token')

  const verified = verifySsoToken(token, secret)
  if (!verified.ok) {
    return reject(verified.error === 'expired' ? 'expired' : 'invalid', verified.error)
  }
  const { claims } = verified

  if (!saved || !statesMatch(saved.state, claims.state)) {
    return reject('state', saved ? 'state mismatch' : 'no state cookie')
  }

  const admin = supabaseAdmin()
  try {
    if (!(await consumeSsoNonce(admin, claims.jti, claims.exp))) {
      return reject('replay')
    }

    const member = await provisionQuaddroMember(admin, claims)
    const tokenHash = await mintSessionTokenHash(admin, member.authEmail)

    const supabase = await createClient()
    const { error } = await supabase.auth.verifyOtp({ type: 'email', token_hash: tokenHash })
    if (error) throw error

    after(async () => {
      try {
        await syncQuaddroPatients(admin, member.accountId)
      } catch (err) {
        console.error('[quaddro-patients] sign-in sync failed:', err instanceof Error ? err.message : 'unknown error')
      }
    })

    const connected = await hasConnectedWhatsApp(admin, member.accountId)
    return relativeRedirect(landingPath(saved.next, connected))
  } catch (err) {
    console.error('[quaddro-sso] sign-in failed:', err instanceof Error ? err.message : 'unknown error')
    return reject('unavailable')
  }
}
