// Shared bits of the Quaddro SSO routes (kept out of the route files so
// they stay unit-testable without Next request plumbing).

import { relativeRedirect } from '@/lib/auth/callback'

/** Where a fresh sign-in lands by default. */
export const DEFAULT_LANDING = '/inbox'

/** Where a workspace without a WhatsApp number is sent first. */
export const CONNECT_WHATSAPP_PATH = '/settings?tab=whatsapp'

export const SSO_ERROR_PATH = '/sso/quaddro/error'

/** Failure reasons the error page knows how to explain. */
export const SSO_FAILURES = [
  'not_configured',
  'invalid',
  'expired',
  'state',
  'replay',
  'unavailable',
] as const
export type SsoFailure = (typeof SSO_FAILURES)[number]

export function isSsoFailure(value: unknown): value is SsoFailure {
  return typeof value === 'string' && (SSO_FAILURES as readonly string[]).includes(value)
}

export function ssoFailure(reason: SsoFailure): Response {
  return relativeRedirect(`${SSO_ERROR_PATH}?reason=${reason}`)
}

/**
 * Landing after a successful sign-in. A workspace with no WhatsApp
 * number yet goes to the connect screen — unless the user was
 * deep-linking somewhere specific.
 */
export function landingPath(next: string, whatsappConnected: boolean): string {
  if (!whatsappConnected && next === DEFAULT_LANDING) return CONNECT_WHATSAPP_PATH
  return next
}
