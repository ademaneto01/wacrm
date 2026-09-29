// ============================================================
// GET /api/sso/quaddro/start[?next=/path]
//
// First hop of the Quaddro SSO: remember a fresh `state` (and where the
// user is headed) in a short-lived HttpOnly cookie, then send the
// browser to the Quaddro panel's authorize page. Quaddro checks its own
// session, signs a handoff token bound to that state and POSTs it back
// to /api/sso/quaddro/callback.
//
// Linked from the Quaddro sidebar (via Quaddro's /whatsapp page) and
// used by the middleware whenever a Quaddro-mode visitor has no
// session, so an expired session silently re-authenticates.
// ============================================================

import { NextResponse } from 'next/server'
import { safeNextPath } from '@/lib/auth/callback'
import { QUADDRO_AUTHORIZE_PATH, isQuaddroMode, quaddroUrl } from '@/lib/quaddro/config'
import { getSsoSecret } from '@/lib/quaddro/sso-token'
import {
  STATE_COOKIE,
  encodeStateCookie,
  isSecureRequest,
  newState,
  stateCookieOptions,
} from '@/lib/quaddro/sso-state'
import { DEFAULT_LANDING, ssoFailure } from '@/lib/quaddro/sso-flow'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  if (!isQuaddroMode() || !getSsoSecret()) return ssoFailure('not_configured')

  const next = safeNextPath(new URL(request.url).searchParams.get('next'), DEFAULT_LANDING)
  const state = newState()

  const authorize = new URL(quaddroUrl(QUADDRO_AUTHORIZE_PATH))
  authorize.searchParams.set('state', state)

  const response = NextResponse.redirect(authorize, 303)
  response.headers.set('Cache-Control', 'no-store')
  response.cookies.set(
    STATE_COOKIE,
    encodeStateCookie(state, next),
    stateCookieOptions(isSecureRequest(request)),
  )
  return response
}
