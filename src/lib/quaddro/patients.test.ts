import { createHmac } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { SupabaseClient } from '@supabase/supabase-js'
import {
  QuaddroPatientsError,
  fetchQuaddroPatients,
  isSyncDue,
  parsePatientsResponse,
  signPatientsToken,
  syncQuaddroPatients,
} from './patients'

const SECRET = 'patients-secret-for-tests-0123456789abcdef'
const BUSINESS_ID = '6f1c2a9e-8b1d-4f0e-9d4a-2b7c3e5f6a10'

function decode(part: string) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
}

describe('signPatientsToken', () => {
  it('signs the contract the Quaddro API verifies', () => {
    const token = signPatientsToken(BUSINESS_ID, SECRET, 1_000)
    const [header, payload, signature] = token.split('.')

    expect(decode(header)).toEqual({ alg: 'HS256', typ: 'JWT' })
    const claims = decode(payload)
    expect(claims).toMatchObject({
      iss: 'wacrm',
      aud: 'quaddro',
      scope: 'patients:read',
      sub: BUSINESS_ID,
      iat: 1_000,
      exp: 1_060,
    })
    expect(typeof claims.jti).toBe('string')
    expect(signature).toBe(
      createHmac('sha256', SECRET).update(`${header}.${payload}`).digest('base64url'),
    )
  })

  it('uses a fresh jti per token', () => {
    const a = decode(signPatientsToken(BUSINESS_ID, SECRET, 1).split('.')[1])
    const b = decode(signPatientsToken(BUSINESS_ID, SECRET, 1).split('.')[1])
    expect(a.jti).not.toBe(b.jti)
  })
})

describe('parsePatientsResponse', () => {
  const data = [{ id: 'c1', name: 'Maria', phone: '5511999999999' }]

  it('reads the superjson success envelope', () => {
    expect(parsePatientsResponse({ json: { result: { code: 200, data } } })).toEqual(data)
  })

  it('reads a plain JSON envelope', () => {
    expect(parsePatientsResponse({ result: { code: 200, data } })).toEqual(data)
  })

  it('drops malformed rows and coerces missing fields', () => {
    expect(
      parsePatientsResponse({
        json: { result: { data: [null, { id: 7 }, { id: 'c2' }, { id: 'c3', name: 'Ana', phone: 1 }] } },
      }),
    ).toEqual([
      { id: 'c2', name: '', phone: '' },
      { id: 'c3', name: 'Ana', phone: '' },
    ])
  })

  it.each([
    ['an error envelope', { error: { code: 401, message: 'Failed to authenticate' } }],
    ['no data array', { json: { result: { data: 'nope' } } }],
    ['garbage', 'nope'],
  ])('rejects %s', (_, body) => {
    expect(() => parsePatientsResponse(body)).toThrow(QuaddroPatientsError)
  })
})

describe('fetchQuaddroPatients', () => {
  const config = { apiUrl: 'http://quaddro.test', secret: SECRET }

  it('POSTs the signed token to the listPatients operation', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ json: { result: { data: [] } } }), { status: 200 }),
    )

    await fetchQuaddroPatients(BUSINESS_ID, config, fetchImpl)

    const [url, init] = fetchImpl.mock.calls[0]
    expect(url).toBe('http://quaddro.test/operations/integrations/wacrm/listPatients')
    expect(init.method).toBe('POST')
    const token = JSON.parse(init.body).data.token as string
    expect(decode(token.split('.')[1]).sub).toBe(BUSINESS_ID)
  })

  it('maps network and HTTP failures to QuaddroPatientsError', async () => {
    await expect(
      fetchQuaddroPatients(BUSINESS_ID, config, vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))),
    ).rejects.toThrow('quaddro api unreachable')
    await expect(
      fetchQuaddroPatients(BUSINESS_ID, config, vi.fn().mockResolvedValue(new Response('x', { status: 404 }))),
    ).rejects.toThrow('quaddro api http 404')
  })
})

describe('isSyncDue', () => {
  const now = Date.parse('2026-09-29T12:00:00Z')

  it('runs when never synced', () => {
    expect(isSyncDue(null, false, now)).toBe(true)
  })

  it('throttles automatic syncs to one a minute and forced ones to one per 10 s', () => {
    const thirtySecondsAgo = new Date(now - 30_000).toISOString()
    expect(isSyncDue(thirtySecondsAgo, false, now)).toBe(false)
    expect(isSyncDue(thirtySecondsAgo, true, now)).toBe(true)
    expect(isSyncDue(new Date(now - 5_000).toISOString(), true, now)).toBe(false)
    expect(isSyncDue(new Date(now - 61_000).toISOString(), false, now)).toBe(true)
  })
})

describe('syncQuaddroPatients', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  function fakeAdmin(link: Record<string, unknown> | null) {
    const eq = vi.fn(() => ({ maybeSingle: async () => ({ data: link, error: null }) }))
    const rpc = vi.fn(async () => ({ data: { patients: 1, inserted: 1 }, error: null }))
    const admin = {
      from: vi.fn(() => ({ select: () => ({ eq }) })),
      rpc,
    } as unknown as SupabaseClient
    return { admin, eq, rpc }
  }

  function configure() {
    vi.stubEnv('QUADDRO_API_URL', 'http://quaddro.test/')
    vi.stubEnv('QUADDRO_API_SECRET', SECRET)
  }

  it('is a no-op when the API is not configured', async () => {
    vi.stubEnv('QUADDRO_API_URL', '')
    const { admin } = fakeAdmin({ quaddro_business_id: BUSINESS_ID })
    await expect(syncQuaddroPatients(admin, 'acc-1')).resolves.toEqual({
      status: 'skipped',
      reason: 'not_configured',
    })
  })

  it('skips accounts that are not a Quaddro business', async () => {
    configure()
    const { admin, eq } = fakeAdmin(null)
    await expect(syncQuaddroPatients(admin, 'acc-1')).resolves.toEqual({
      status: 'skipped',
      reason: 'not_linked',
    })
    expect(eq).toHaveBeenCalledWith('account_id', 'acc-1')
  })

  it('respects the throttle', async () => {
    configure()
    const { admin, rpc } = fakeAdmin({
      quaddro_business_id: BUSINESS_ID,
      patients_synced_at: new Date().toISOString(),
    })
    const fetchImpl = vi.fn()
    await expect(syncQuaddroPatients(admin, 'acc-1', { fetchImpl })).resolves.toEqual({
      status: 'skipped',
      reason: 'recent',
    })
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(rpc).not.toHaveBeenCalled()
  })

  it('fetches the linked business and hands the list to the RPC for the same account', async () => {
    configure()
    const { admin, rpc } = fakeAdmin({ quaddro_business_id: BUSINESS_ID, patients_synced_at: null })
    const patients = [{ id: 'c1', name: 'Maria', phone: '5511999999999' }]
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ json: { result: { data: patients } } }), { status: 200 }),
    )

    const outcome = await syncQuaddroPatients(admin, 'acc-1', { fetchImpl })

    const token = JSON.parse(fetchImpl.mock.calls[0][1].body).data.token as string
    expect(decode(token.split('.')[1]).sub).toBe(BUSINESS_ID)
    expect(rpc).toHaveBeenCalledWith('quaddro_sync_patients', {
      p_account_id: 'acc-1',
      p_patients: patients,
    })
    expect(outcome).toEqual({ status: 'synced', counts: { patients: 1, inserted: 1 } })
  })
})
