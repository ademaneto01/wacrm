import { describe, expect, it, vi } from 'vitest'
import type { SupabaseClient } from '@supabase/supabase-js'
import {
  ProvisioningError,
  consumeSsoNonce,
  mintSessionTokenHash,
  provisionQuaddroMember,
  syntheticEmail,
} from './provision'
import type { QuaddroSsoClaims } from './sso-token'

const claims: QuaddroSsoClaims = {
  iss: 'quaddro',
  aud: 'wacrm',
  iat: 1,
  exp: 61,
  jti: 'jti-0000000000000001',
  state: 'S'.repeat(43),
  sub: 'member-1',
  bid: 'biz-1',
  bname: 'Clínica X',
  name: 'Ana',
  email: 'ana@example.com',
  role: 'employee',
}

/**
 * Minimal fake of the bits of the service-role client provisioning
 * uses. `users` maps synthetic email → id (what quaddro_auth_user_id
 * would find in auth.users).
 */
function fakeAdmin({
  users = {} as Record<string, string>,
  createUserFails = false,
  raceWinner = null as string | null,
  provisionError = null as unknown,
} = {}) {
  const created: Array<Record<string, unknown>> = []
  const rpcCalls: Array<[string, Record<string, unknown>]> = []
  let lookups = 0
  const admin = {
    rpc: vi.fn(async (fn: string, args: Record<string, unknown>) => {
      rpcCalls.push([fn, args])
      if (fn === 'quaddro_auth_user_id') {
        lookups++
        const email = args.p_email as string
        // Simulate a concurrent request creating the user between our
        // first lookup and our createUser call.
        if (raceWinner && lookups > 1 && email.startsWith('member-')) return { data: raceWinner, error: null }
        return { data: users[email] ?? null, error: null }
      }
      if (fn === 'quaddro_provision_member') {
        return provisionError ? { data: null, error: provisionError } : { data: 'account-1', error: null }
      }
      if (fn === 'quaddro_consume_sso_nonce') return { data: true, error: null }
      throw new Error(`unexpected rpc ${fn}`)
    }),
    auth: {
      admin: {
        createUser: vi.fn(async (attrs: Record<string, unknown>) => {
          created.push(attrs)
          if (createUserFails) return { data: { user: null }, error: { message: 'email_exists' } }
          return { data: { user: { id: `new-${created.length}` } }, error: null }
        }),
        generateLink: vi.fn(async () => ({
          data: { properties: { hashed_token: 'hash-123' } },
          error: null,
        })),
      },
    },
  }
  return { admin: admin as unknown as SupabaseClient, created, rpcCalls }
}

describe('provisionQuaddroMember', () => {
  it('first access creates a banned system owner and the member, then links them', async () => {
    const { admin, created, rpcCalls } = fakeAdmin()
    const result = await provisionQuaddroMember(admin, claims)

    expect(created).toHaveLength(2)
    expect(created[0]).toMatchObject({
      email: syntheticEmail('owner', 'biz-1'),
      email_confirm: true,
      ban_duration: '876000h',
    })
    expect(created[1]).toMatchObject({ email: syntheticEmail('member', 'biz-1', 'member-1') })
    expect(created[1]).not.toHaveProperty('ban_duration')

    const provision = rpcCalls.find(([fn]) => fn === 'quaddro_provision_member')?.[1]
    expect(provision).toMatchObject({
      p_business_id: 'biz-1',
      p_business_name: 'Clínica X',
      p_owner_user_id: 'new-1',
      p_member_id: 'member-1',
      p_user_id: 'new-2',
      p_role: 'agent',
      p_email: 'ana@example.com',
    })
    expect(result).toEqual({
      userId: 'new-2',
      accountId: 'account-1',
      authEmail: syntheticEmail('member', 'biz-1', 'member-1'),
    })
  })

  it('later accesses reuse existing users (no createUser)', async () => {
    const { admin, created } = fakeAdmin({
      users: {
        [syntheticEmail('owner', 'biz-1')]: 'owner-id',
        [syntheticEmail('member', 'biz-1', 'member-1')]: 'member-id',
      },
    })
    const result = await provisionQuaddroMember(admin, { ...claims, role: 'owner' })
    expect(created).toHaveLength(0)
    expect(result.userId).toBe('member-id')
  })

  it('recovers when a concurrent sign-in created the member first', async () => {
    const { admin } = fakeAdmin({
      users: { [syntheticEmail('owner', 'biz-1')]: 'owner-id' },
      createUserFails: true,
      raceWinner: 'winner-id',
    })
    const result = await provisionQuaddroMember(admin, claims)
    expect(result.userId).toBe('winner-id')
  })

  it('surfaces a user-creation failure it cannot recover from', async () => {
    const { admin } = fakeAdmin({ createUserFails: true })
    await expect(provisionQuaddroMember(admin, claims)).rejects.toBeInstanceOf(ProvisioningError)
  })

  it('surfaces a membership failure', async () => {
    const { admin } = fakeAdmin({ provisionError: { message: 'boom' } })
    await expect(provisionQuaddroMember(admin, claims)).rejects.toThrow(/membership/)
  })
})

describe('session + nonce helpers', () => {
  it('mints a token hash without sending email', async () => {
    const { admin } = fakeAdmin()
    await expect(mintSessionTokenHash(admin, 'x@sso.quaddro.invalid')).resolves.toBe('hash-123')
  })

  it('passes the token expiry to the nonce store', async () => {
    const { admin, rpcCalls } = fakeAdmin()
    await expect(consumeSsoNonce(admin, 'jti-1', 1_800_000_000)).resolves.toBe(true)
    expect(rpcCalls[0]).toEqual([
      'quaddro_consume_sso_nonce',
      { p_jti: 'jti-1', p_expires_at: new Date(1_800_000_000_000).toISOString() },
    ])
  })
})
