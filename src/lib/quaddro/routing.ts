// Middleware rules for Quaddro mode (see src/lib/quaddro/config.ts).
// Pure functions so they can be unit tested without a request.

import { SSO_START_PATH } from './config'

/**
 * Password / signup / invitation pages. In Quaddro mode identity and
 * team membership belong to Quaddro, so these are never shown.
 */
export function isPasswordAuthPage(pathname: string): boolean {
  return (
    pathname === '/login' ||
    pathname === '/signup' ||
    pathname === '/forgot-password' ||
    pathname === '/reset-password' ||
    pathname === '/join' ||
    pathname.startsWith('/join/')
  )
}

/**
 * Team-management endpoints that would let WACRM drift from Quaddro:
 * invitations (could pull a user into another business's workspace),
 * ownership transfer, and member role changes / removals (overwritten
 * by the next SSO sign-in anyway). Reading the member list stays open.
 */
export function isQuaddroManagedApi(pathname: string, method: string): boolean {
  if (pathname.startsWith('/api/invitations/')) return true
  if (pathname === '/api/account/invitations' || pathname.startsWith('/api/account/invitations/')) {
    return true
  }
  if (pathname === '/api/account/transfer-ownership') return true
  if (pathname.startsWith('/api/account/members/') && method.toUpperCase() !== 'GET') return true
  return false
}

/** SSO entry that returns the user to `pathWithSearch` afterwards. */
export function ssoStartPath(pathWithSearch: string): string {
  return `${SSO_START_PATH}?next=${encodeURIComponent(pathWithSearch)}`
}

/**
 * Dashboard sections switched off for the Quaddro MVP. Only the panel,
 * inbox, contacts, notifications and pipelines (plus settings, needed
 * to connect WhatsApp) stay reachable. Drop a path from this list to
 * bring its section back — the sidebar and dashboard read it too.
 */
export const QUADDRO_DISABLED_PATHS: readonly string[] = [
  '/broadcasts',
  '/automations',
  '/flows',
  '/agents',
]

/** True for a page (or sub-page) of a section disabled in Quaddro mode. */
export function isQuaddroDisabledPage(pathname: string): boolean {
  return QUADDRO_DISABLED_PATHS.some(
    (path) => pathname === path || pathname.startsWith(`${path}/`),
  )
}
