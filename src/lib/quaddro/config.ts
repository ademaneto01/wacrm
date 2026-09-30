// ============================================================
// Quaddro integration switches.
//
// Setting NEXT_PUBLIC_QUADDRO_APP_URL turns this deployment into the
// "WhatsApp" module of the Quaddro panel:
//   - sign-in happens only through Quaddro SSO (no password login,
//     signup, password reset or invitations — Quaddro owns identity
//     and team membership);
//   - the UI wears the Quaddro brand (logo, blue accent, light mode);
//   - the sidebar links back to the Quaddro panel.
// Unset, the app behaves exactly like upstream wacrm.
//
// NEXT_PUBLIC_* is inlined at build time, so the switch is safe to read
// from client components too. The shared secret is server-only and
// lives in src/lib/quaddro/sso-token.ts.
// ============================================================

/** Quaddro panel origin (web-pro-app), without a trailing slash, or ''. */
export function quaddroAppUrl(): string {
  return (process.env.NEXT_PUBLIC_QUADDRO_APP_URL ?? '').trim().replace(/\/+$/, '')
}

export function isQuaddroMode(): boolean {
  return quaddroAppUrl().length > 0
}

/**
 * AI features (inbox draft button + hint, auto-reply banner, the AI
 * agents section) are off for the Quaddro MVP. Flip this to bring them
 * back.
 */
export function isAiEnabled(): boolean {
  return !isQuaddroMode()
}

/** Absolute URL of a Quaddro panel page. */
export function quaddroUrl(path: string): string {
  return `${quaddroAppUrl()}${path.startsWith('/') ? path : `/${path}`}`
}

/** The Quaddro page that re-launches this module (sidebar entry). */
export const QUADDRO_WHATSAPP_PATH = '/whatsapp'

/** The Quaddro page that signs the handoff token. */
export const QUADDRO_AUTHORIZE_PATH = '/whatsapp/authorize'

/** Where the SSO dance starts on this side. */
export const SSO_START_PATH = '/api/sso/quaddro/start'
