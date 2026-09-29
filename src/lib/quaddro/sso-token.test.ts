import { describe, expect, it } from 'vitest'
import {
  MAX_LIFETIME_S,
  mapQuaddroRole,
  signSsoToken,
  verifySsoToken,
  type QuaddroSsoClaims,
} from './sso-token'

const SECRET = 's'.repeat(48)
const NOW = 1_800_000_000

function claims(overrides: Partial<Record<keyof QuaddroSsoClaims, unknown>> = {}): QuaddroSsoClaims {
  return {
    iss: 'quaddro',
    aud: 'wacrm',
    iat: NOW,
    exp: NOW + 60,
    jti: '0f0e6f7a-8a4c-4b43-9a53-2f2c3c5a9b11',
    state: 'A'.repeat(43),
    sub: '6d1c1f0a-1111-4b43-9a53-2f2c3c5a9b11',
    bid: '7e2d2f1b-2222-4b43-9a53-2f2c3c5a9b11',
    bname: 'Clínica Sorriso',
    name: 'Ana Souza',
    email: 'ana@example.com',
    role: 'employee',
    ...overrides,
  } as QuaddroSsoClaims
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url')

describe('verifySsoToken', () => {
  it('accepts a well-formed token and returns trimmed claims', () => {
    const token = signSsoToken(claims({ bname: '  Clínica Sorriso  ' }), SECRET)
    const result = verifySsoToken(token, SECRET, NOW + 5)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.claims.bname).toBe('Clínica Sorriso')
      expect(result.claims.role).toBe('employee')
    }
  })

  it('rejects a token signed with another secret', () => {
    const token = signSsoToken(claims(), 'x'.repeat(48))
    expect(verifySsoToken(token, SECRET, NOW)).toEqual({ ok: false, error: 'bad_signature' })
  })

  it('rejects a tampered payload', () => {
    const [h, , s] = signSsoToken(claims(), SECRET).split('.')
    const forged = `${h}.${b64(claims({ bid: 'another-business' }))}.${s}`
    expect(verifySsoToken(forged, SECRET, NOW)).toEqual({ ok: false, error: 'bad_signature' })
  })

  it('rejects alg=none and other algorithms', () => {
    const payload = b64(claims())
    expect(verifySsoToken(`${b64({ alg: 'none' })}.${payload}.`, SECRET, NOW).ok).toBe(false)
    expect(verifySsoToken(`${b64({ alg: 'none' })}.${payload}.x`, SECRET, NOW)).toEqual({
      ok: false,
      error: 'malformed',
    })
    expect(verifySsoToken(`${b64({ alg: 'HS512' })}.${payload}.x`, SECRET, NOW)).toEqual({
      ok: false,
      error: 'malformed',
    })
  })

  it.each([
    ['', 'malformed'],
    ['a.b', 'malformed'],
    ['a.b.c.d', 'malformed'],
    ['!!.??.**', 'malformed'],
  ])('rejects malformed input %j', (token, error) => {
    expect(verifySsoToken(token, SECRET, NOW)).toEqual({ ok: false, error })
  })

  it('rejects an expired token (beyond the clock skew)', () => {
    const token = signSsoToken(claims(), SECRET)
    expect(verifySsoToken(token, SECRET, NOW + 60 + 31)).toEqual({ ok: false, error: 'expired' })
    expect(verifySsoToken(token, SECRET, NOW + 60 + 29).ok).toBe(true)
  })

  it('rejects a token issued in the future', () => {
    const token = signSsoToken(claims(), SECRET)
    expect(verifySsoToken(token, SECRET, NOW - 120)).toEqual({ ok: false, error: 'not_yet_valid' })
  })

  it('rejects a lifetime longer than the maximum', () => {
    const token = signSsoToken(claims({ exp: NOW + MAX_LIFETIME_S + 1 }), SECRET)
    expect(verifySsoToken(token, SECRET, NOW)).toEqual({ ok: false, error: 'lifetime_too_long' })
  })

  it('rejects the wrong issuer or audience', () => {
    expect(verifySsoToken(signSsoToken(claims({ iss: 'x' }), SECRET), SECRET, NOW)).toEqual({
      ok: false,
      error: 'wrong_issuer',
    })
    expect(verifySsoToken(signSsoToken(claims({ aud: 'x' }), SECRET), SECRET, NOW)).toEqual({
      ok: false,
      error: 'wrong_audience',
    })
  })

  it.each([
    ['unknown role', { role: 'superuser' }],
    ['short jti', { jti: 'abc' }],
    ['short state', { state: 'abc' }],
    ['business id with odd characters', { bid: '../../etc' }],
    ['empty business name', { bname: '   ' }],
    ['non-integer exp', { exp: NOW + 0.5 }],
    ['missing member id', { sub: undefined }],
  ])('rejects %s', (_label, overrides) => {
    const token = signSsoToken(claims(overrides), SECRET)
    expect(verifySsoToken(token, SECRET, NOW)).toEqual({ ok: false, error: 'invalid_claims' })
  })
})

describe('mapQuaddroRole', () => {
  it('never hands out owner and maps staff to agent', () => {
    expect(mapQuaddroRole('owner')).toBe('admin')
    expect(mapQuaddroRole('admin')).toBe('admin')
    expect(mapQuaddroRole('assistant')).toBe('agent')
    expect(mapQuaddroRole('employee')).toBe('agent')
  })
})
