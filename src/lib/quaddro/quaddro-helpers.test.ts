import { afterEach, describe, expect, it, vi } from 'vitest'
import { isQuaddroMode, quaddroAppUrl, quaddroUrl } from './config'
import { isPasswordAuthPage, isQuaddroDisabledPage, isQuaddroManagedApi, ssoStartPath } from './routing'
import {
  decodeStateCookie,
  encodeStateCookie,
  isSecureRequest,
  newState,
  stateCookieOptions,
  statesMatch,
} from './sso-state'
import { CONNECT_WHATSAPP_PATH, DEFAULT_LANDING, isSsoFailure, landingPath } from './sso-flow'
import { syntheticEmail } from './provision'

afterEach(() => vi.unstubAllEnvs())

describe('config', () => {
  it('is off when NEXT_PUBLIC_QUADDRO_APP_URL is unset', () => {
    vi.stubEnv('NEXT_PUBLIC_QUADDRO_APP_URL', '')
    expect(isQuaddroMode()).toBe(false)
  })

  it('normalises the Quaddro URL and joins paths', () => {
    vi.stubEnv('NEXT_PUBLIC_QUADDRO_APP_URL', ' https://pro.example.com/// ')
    expect(isQuaddroMode()).toBe(true)
    expect(quaddroAppUrl()).toBe('https://pro.example.com')
    expect(quaddroUrl('/whatsapp')).toBe('https://pro.example.com/whatsapp')
    expect(quaddroUrl('whatsapp')).toBe('https://pro.example.com/whatsapp')
  })
})

describe('routing', () => {
  it.each(['/login', '/signup', '/forgot-password', '/reset-password', '/join', '/join/abc'])(
    '%s is a password/invite page',
    (path) => expect(isPasswordAuthPage(path)).toBe(true),
  )

  it.each(['/inbox', '/joinery', '/settings', '/login-help'])('%s is not', (path) =>
    expect(isPasswordAuthPage(path)).toBe(false),
  )

  it.each(['/broadcasts', '/broadcasts/new', '/automations/abc', '/flows', '/agents/x'])(
    '%s is disabled for the MVP',
    (path) => expect(isQuaddroDisabledPage(path)).toBe(true),
  )

  it.each(['/dashboard', '/inbox', '/contacts', '/notifications', '/pipelines', '/settings', '/agentsx'])(
    '%s stays enabled',
    (path) => expect(isQuaddroDisabledPage(path)).toBe(false),
  )

  it('closes team-management APIs but keeps reads and other APIs open', () => {
    expect(isQuaddroManagedApi('/api/account/invitations', 'POST')).toBe(true)
    expect(isQuaddroManagedApi('/api/account/invitations/123', 'DELETE')).toBe(true)
    expect(isQuaddroManagedApi('/api/invitations/tok/redeem', 'POST')).toBe(true)
    expect(isQuaddroManagedApi('/api/account/transfer-ownership', 'POST')).toBe(true)
    expect(isQuaddroManagedApi('/api/account/members/u1', 'PATCH')).toBe(true)
    expect(isQuaddroManagedApi('/api/account/members/u1', 'DELETE')).toBe(true)
    expect(isQuaddroManagedApi('/api/account/members', 'GET')).toBe(false)
    expect(isQuaddroManagedApi('/api/account', 'PATCH')).toBe(false)
    expect(isQuaddroManagedApi('/api/whatsapp/send', 'POST')).toBe(false)
  })

  it('builds the SSO start path with an encoded return path', () => {
    expect(ssoStartPath('/contacts?tab=all')).toBe('/api/sso/quaddro/start?next=%2Fcontacts%3Ftab%3Dall')
  })
})

describe('state cookie', () => {
  it('generates unguessable 256-bit states', () => {
    const a = newState()
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(newState()).not.toBe(a)
  })

  it('round-trips state and next', () => {
    const raw = encodeStateCookie('abc', '/contacts?x=1~2')
    expect(decodeStateCookie(raw, '/inbox')).toEqual({ state: 'abc', next: '/contacts?x=1~2' })
  })

  it('sanitises an open-redirect next on the way out', () => {
    expect(decodeStateCookie(encodeStateCookie('abc', '//evil.example'), '/inbox')?.next).toBe('/inbox')
    expect(decodeStateCookie(encodeStateCookie('abc', 'https://evil.example'), '/inbox')?.next).toBe('/inbox')
  })

  it.each([undefined, '', 'nostate', '~/inbox', 'abc~%E0%A4%A'])('rejects %j', (raw) => {
    expect(decodeStateCookie(raw, '/inbox')).toBeNull()
  })

  it('compares states in constant time and exactly', () => {
    expect(statesMatch('abc', 'abc')).toBe(true)
    expect(statesMatch('abc', 'abd')).toBe(false)
    expect(statesMatch('abc', 'abcd')).toBe(false)
  })

  it('uses SameSite=None+Secure over HTTPS and Lax on plain HTTP', () => {
    expect(stateCookieOptions(true)).toMatchObject({ secure: true, sameSite: 'none', httpOnly: true })
    expect(stateCookieOptions(false)).toMatchObject({ secure: false, sameSite: 'lax', httpOnly: true })
  })

  it('detects HTTPS directly or behind a proxy', () => {
    expect(isSecureRequest(new Request('https://a.example/x'))).toBe(true)
    expect(isSecureRequest(new Request('http://a.example/x'))).toBe(false)
    expect(
      isSecureRequest(new Request('http://a.example/x', { headers: { 'x-forwarded-proto': 'https' } })),
    ).toBe(true)
  })
})

describe('landing', () => {
  it('sends a workspace without WhatsApp to the connect screen by default', () => {
    expect(landingPath(DEFAULT_LANDING, false)).toBe(CONNECT_WHATSAPP_PATH)
    expect(landingPath(DEFAULT_LANDING, true)).toBe(DEFAULT_LANDING)
  })

  it('honours an explicit deep link either way', () => {
    expect(landingPath('/contacts', false)).toBe('/contacts')
  })

  it('knows its failure reasons', () => {
    expect(isSsoFailure('replay')).toBe(true)
    expect(isSsoFailure('<script>')).toBe(false)
  })
})

describe('syntheticEmail', () => {
  it('is deterministic per identity and never collides across kinds or businesses', () => {
    const a = syntheticEmail('member', 'biz-1', 'm-1')
    expect(syntheticEmail('member', 'biz-1', 'm-1')).toBe(a)
    expect(syntheticEmail('member', 'biz-2', 'm-1')).not.toBe(a)
    expect(syntheticEmail('owner', 'biz-1')).not.toBe(syntheticEmail('member', 'biz-1'))
    expect(a).toMatch(/^member-[0-9a-f]{40}@sso\.quaddro\.invalid$/)
  })
})
