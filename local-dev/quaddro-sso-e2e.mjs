#!/usr/bin/env node
// ============================================================
// API-level end-to-end check of the Quaddro SSO against a RUNNING
// local WACRM (npm run dev on :3100) + the local Supabase in local-dev/.
//
// It plays the Quaddro side (signs handoff tokens with the shared
// secret, exactly like web-pro-app's app/utils/wacrm.server.ts) and
// asserts, over real HTTP and real Postgres/RLS:
//   SSO:          valid / tampered / expired / wrong audience /
//                 wrong issuer / missing state cookie / state mismatch /
//                 replay / missing token / start + health endpoints
//   provisioning: first access, second access, existing org/user/
//                 membership (no duplicates), role mapping + re-sync,
//                 business rename re-sync
//   tenancy:      same business → same account; other business →
//                 isolated (contacts, conversations, whatsapp_config,
//                 accounts, cross-tenant insert refused by RLS)
//
// Usage (from the wacrm repo root):
//   node --env-file=.env.development.local local-dev/quaddro-sso-e2e.mjs [http://localhost:3100]
//
// DEVELOPMENT ONLY: it creates throwaway Quaddro businesses (random ids)
// in the local database. Never point it at a shared or production stack.
// ============================================================

import { createHmac, randomUUID } from 'node:crypto'
import assert from 'node:assert/strict'

const BASE = process.argv[2] ?? 'http://localhost:3100'
const SECRET = process.env.QUADDRO_SSO_SECRET
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY
if (!SECRET || !SUPABASE_URL || !ANON || !SERVICE) {
  console.error('Missing env: run with --env-file=.env.development.local')
  process.exit(2)
}
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(SUPABASE_URL)) {
  console.error(`Refusing to run against a non-local Supabase (${SUPABASE_URL}).`)
  process.exit(2)
}

// ---------- tiny test harness ----------
let passed = 0
let failed = 0
async function test(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  ✓ ${name}`)
  } catch (err) {
    failed++
    console.log(`  ✗ ${name}\n      ${err?.message ?? err}`)
  }
}

// ---------- Quaddro side: token signing ----------
const b64 = (v) => Buffer.from(v).toString('base64url')
function sign(claims, secret = SECRET) {
  const input = `${b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64(JSON.stringify(claims))}`
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`
}
function claimsFor(who, state, overrides = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: 'quaddro',
    aud: 'wacrm',
    iat: now,
    exp: now + 60,
    jti: randomUUID(),
    state,
    sub: who.memberId,
    bid: who.businessId,
    bname: who.businessName,
    name: who.name,
    email: who.email,
    role: who.role,
    ...overrides,
  }
}

// ---------- HTTP helpers ----------
function setCookies(res) {
  return res.headers.getSetCookie?.() ?? []
}
function cookieHeader(list) {
  return list
    .map((c) => c.split(';')[0])
    .filter((c) => !c.endsWith('='))
    .join('; ')
}

/** GET /start → { state, cookie } */
async function start(next) {
  const url = new URL('/api/sso/quaddro/start', BASE)
  if (next) url.searchParams.set('next', next)
  const res = await fetch(url, { redirect: 'manual' })
  assert.equal(res.status, 303, `start status ${res.status}`)
  const location = new URL(res.headers.get('location'))
  const state = location.searchParams.get('state')
  const cookies = setCookies(res)
  return { res, location, state, cookie: cookieHeader(cookies), rawCookies: cookies }
}

/** POST /callback with a token (and optionally a state cookie). */
async function callback(token, cookie) {
  const body = new URLSearchParams()
  if (token != null) body.set('token', token)
  const res = await fetch(new URL('/api/sso/quaddro/callback', BASE), {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(cookie ? { cookie } : {}),
    },
    body,
  })
  return { status: res.status, location: res.headers.get('location'), cookies: setCookies(res) }
}

/** Full happy-path sign-in. Returns the Supabase access token. */
async function signIn(who, overrides) {
  const s = await start()
  const r = await callback(sign(claimsFor(who, s.state, overrides)), s.cookie)
  assert.equal(r.status, 303)
  assert.ok(!r.location.startsWith('/sso/quaddro/error'), `sign-in failed → ${r.location}`)
  return { location: r.location, accessToken: accessTokenFrom(r.cookies) }
}

/** Pull the access token out of @supabase/ssr's (possibly chunked) auth cookie. */
function accessTokenFrom(cookies) {
  const parts = cookies
    .map((c) => c.split(';')[0])
    .filter((c) => /^sb-[^=]+-auth-token(\.\d+)?=/.test(c) && !c.endsWith('='))
    .sort()
    .map((c) => c.slice(c.indexOf('=') + 1))
  assert.ok(parts.length > 0, 'no Supabase auth cookie was set')
  let raw = decodeURIComponent(parts.join(''))
  if (raw.startsWith('base64-')) raw = Buffer.from(raw.slice(7), 'base64url').toString('utf8')
  const session = JSON.parse(raw)
  assert.ok(session.access_token, 'session has no access_token')
  return session.access_token
}

// ---------- Supabase REST helpers ----------
async function rest(path, { token, method = 'GET', body, service = false } = {}) {
  const key = service ? SERVICE : ANON
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: key,
      authorization: `Bearer ${service ? SERVICE : token}`,
      'content-type': 'application/json',
      prefer: 'return=representation',
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  return { status: res.status, data: text ? JSON.parse(text) : null }
}
const jwtSub = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).sub
// Members can read every profile in their account, so filter to "me".
const myProfile = async (token) =>
  (await rest(`profiles?select=user_id,account_id,account_role,full_name,email&user_id=eq.${jwtSub(token)}`, { token })).data

// ---------- fixtures ----------
const run = randomUUID().slice(0, 8)
const bizX = { businessId: randomUUID(), businessName: `Clínica X ${run}` }
const bizY = { businessId: randomUUID(), businessName: `Studio Y ${run}` }
const A = { ...bizX, memberId: randomUUID(), name: 'Ana Owner', email: `ana.${run}@example.com`, role: 'owner' }
const B = { ...bizX, memberId: randomUUID(), name: 'Bruno Employee', email: `bruno.${run}@example.com`, role: 'employee' }
const C = { ...bizY, memberId: randomUUID(), name: 'Carla Admin', email: `carla.${run}@example.com`, role: 'admin' }

console.log(`Quaddro SSO e2e against ${BASE} (run ${run})\n`)

console.log('SSO endpoints')
await test('health reports ready', async () => {
  const res = await fetch(new URL('/api/sso/quaddro/health', BASE))
  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), { ok: true })
})
await test('start redirects to Quaddro authorize with a state and sets an HttpOnly state cookie', async () => {
  const s = await start('/contacts')
  assert.equal(`${s.location.origin}${s.location.pathname}`, `${process.env.NEXT_PUBLIC_QUADDRO_APP_URL}/whatsapp/authorize`)
  assert.match(s.state, /^[A-Za-z0-9_-]{43}$/)
  const c = s.rawCookies.find((x) => x.startsWith('wacrm_quaddro_sso='))
  assert.ok(c, 'state cookie missing')
  assert.match(c, /HttpOnly/i)
  assert.match(c, /Path=\/api\/sso\/quaddro/i)
  assert.match(c, /SameSite=lax/i)
})
await test('start ignores an open-redirect `next`', async () => {
  const s = await start('//evil.example/x')
  // Next URL-encodes cookie values on top of our own encoding.
  const c = decodeURIComponent(decodeURIComponent(s.rawCookies.find((x) => x.startsWith('wacrm_quaddro_sso='))))
  assert.ok(c.includes('~/inbox'), 'next was not sanitised to the default')
})

console.log('\nSSO token validation')
const reason = (r) => new URL(r.location, BASE).searchParams.get('reason')
await test('missing token → invalid', async () => {
  const s = await start()
  assert.equal(reason(await callback(null, s.cookie)), 'invalid')
})
await test('garbage token → invalid', async () => {
  const s = await start()
  assert.equal(reason(await callback('not.a.jwt', s.cookie)), 'invalid')
})
await test('tampered payload (signature mismatch) → invalid', async () => {
  const s = await start()
  const [h, , sig] = sign(claimsFor(A, s.state)).split('.')
  const forged = b64(JSON.stringify(claimsFor({ ...A, role: 'owner', businessId: bizY.businessId }, s.state)))
  assert.equal(reason(await callback(`${h}.${forged}.${sig}`, s.cookie)), 'invalid')
})
await test('token signed with another secret → invalid', async () => {
  const s = await start()
  assert.equal(reason(await callback(sign(claimsFor(A, s.state), 'x'.repeat(48)), s.cookie)), 'invalid')
})
await test('alg=none token → invalid', async () => {
  const s = await start()
  const t = `${b64(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64(JSON.stringify(claimsFor(A, s.state)))}.`
  assert.equal(reason(await callback(t, s.cookie)), 'invalid')
})
await test('expired token → expired', async () => {
  const s = await start()
  const now = Math.floor(Date.now() / 1000)
  assert.equal(reason(await callback(sign(claimsFor(A, s.state, { iat: now - 600, exp: now - 540 })), s.cookie)), 'expired')
})
await test('token living longer than 120 s → invalid', async () => {
  const s = await start()
  const now = Math.floor(Date.now() / 1000)
  assert.equal(reason(await callback(sign(claimsFor(A, s.state, { exp: now + 3600 })), s.cookie)), 'invalid')
})
await test('wrong audience → invalid', async () => {
  const s = await start()
  assert.equal(reason(await callback(sign(claimsFor(A, s.state, { aud: 'other-app' })), s.cookie)), 'invalid')
})
await test('wrong issuer → invalid', async () => {
  const s = await start()
  assert.equal(reason(await callback(sign(claimsFor(A, s.state, { iss: 'someone-else' })), s.cookie)), 'invalid')
})
await test('unknown role → invalid', async () => {
  const s = await start()
  assert.equal(reason(await callback(sign(claimsFor({ ...A, role: 'superuser' }, s.state)), s.cookie)), 'invalid')
})
await test('no state cookie (login-CSRF attempt) → state', async () => {
  const s = await start()
  assert.equal(reason(await callback(sign(claimsFor(A, s.state)), undefined)), 'state')
})
await test("state from another browser's cookie → state", async () => {
  const mine = await start()
  const theirs = await start()
  assert.equal(reason(await callback(sign(claimsFor(A, theirs.state)), mine.cookie)), 'state')
})
await test('replayed token → replay', async () => {
  const s = await start()
  const token = sign(claimsFor(A, s.state))
  const first = await callback(token, s.cookie)
  assert.ok(!first.location.startsWith('/sso/'), `first use failed → ${first.location}`)
  assert.equal(reason(await callback(token, s.cookie)), 'replay')
})
await test('rejected attempts create no session cookie', async () => {
  const s = await start()
  const r = await callback(sign(claimsFor(A, s.state), 'y'.repeat(48)), s.cookie)
  assert.ok(!r.cookies.some((c) => /^sb-[^=]+-auth-token/.test(c) && !/^sb-[^=]+-auth-token[^=]*=;/.test(c)))
})

console.log('\nProvisioning')
let tokA, tokB, tokC, accountX, accountY, userA
await test('first access (A, owner of X) → lands on the WhatsApp connect screen', async () => {
  const r = await signIn(A)
  tokA = r.accessToken
  assert.equal(r.location, '/settings?tab=whatsapp')
})
await test('A is an admin of an account named after business X', async () => {
  const [p] = await myProfile(tokA)
  assert.equal(p.account_role, 'admin')
  assert.equal(p.full_name, A.name)
  assert.equal(p.email, A.email)
  accountX = p.account_id
  userA = p.user_id
  const acc = (await rest(`accounts?select=id,name&id=eq.${accountX}`, { token: tokA })).data
  assert.equal(acc[0].name, bizX.businessName)
})
await test('second access of A → same user, same account', async () => {
  const r = await signIn(A)
  const [p] = await myProfile(r.accessToken)
  assert.equal(p.account_id, accountX)
  tokA = r.accessToken
})
await test('deep link survives the SSO bounce', async () => {
  const s = await start('/contacts?tab=all')
  const r = await callback(sign(claimsFor(A, s.state)), s.cookie)
  assert.equal(r.location, '/contacts?tab=all')
})
await test('B (employee of X) joins the SAME account as an agent', async () => {
  tokB = (await signIn(B)).accessToken
  const [p] = await myProfile(tokB)
  assert.equal(p.account_id, accountX)
  assert.equal(p.account_role, 'agent')
})
await test('C (admin of Y) gets a DIFFERENT account', async () => {
  tokC = (await signIn(C)).accessToken
  const [p] = await myProfile(tokC)
  accountY = p.account_id
  assert.notEqual(accountY, accountX)
  assert.equal(p.account_role, 'admin')
})
await test('no duplicates after repeated sign-ins (links, accounts, profiles)', async () => {
  await signIn(A)
  await signIn(B)
  await signIn(B)
  const links = (await rest(`quaddro_business_links?select=account_id&quaddro_business_id=in.(${bizX.businessId},${bizY.businessId})`, { service: true })).data
  assert.equal(links.length, 2)
  const members = (await rest(`quaddro_member_links?select=user_id&quaddro_business_id=eq.${bizX.businessId}`, { service: true })).data
  assert.equal(members.length, 2)
  const profilesX = (await rest(`profiles?select=user_id,account_role&account_id=eq.${accountX}`, { service: true })).data
  // Ana + Bruno + the business's system owner.
  assert.equal(profilesX.length, 3)
  assert.equal(profilesX.filter((p) => p.account_role === 'owner').length, 1)
  const owned = (await rest(`accounts?select=id&name=eq.${encodeURIComponent(bizX.businessName)}`, { service: true })).data
  assert.equal(owned.length, 1)
})
await test('the system owner cannot sign in (banned)', async () => {
  const [owner] = (await rest(`profiles?select=user_id&account_id=eq.${accountX}&account_role=eq.owner`, { service: true })).data
  const res = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${owner.user_id}`, {
    headers: { apikey: SERVICE, authorization: `Bearer ${SERVICE}` },
  })
  const user = await res.json()
  assert.ok(user.banned_until && new Date(user.banned_until) > new Date(Date.now() + 50 * 365 * 864e5))
})
await test('role change in Quaddro is re-synced on next sign-in (employee → admin)', async () => {
  tokB = (await signIn({ ...B, role: 'admin' })).accessToken
  const [p] = await myProfile(tokB)
  assert.equal(p.account_role, 'admin')
  tokB = (await signIn(B)).accessToken
  assert.equal((await myProfile(tokB))[0].account_role, 'agent')
})
await test('business rename in Quaddro is re-synced', async () => {
  const renamed = `${bizX.businessName} (novo nome)`
  await signIn({ ...A, businessName: renamed })
  const acc = (await rest(`accounts?select=name&id=eq.${accountX}`, { token: tokA })).data
  assert.equal(acc[0].name, renamed)
  await signIn(A)
})
await test('same Quaddro member in two businesses → two isolated workspaces', async () => {
  const aInY = { ...A, ...bizY, role: 'employee' }
  const tok = (await signIn(aInY)).accessToken
  const [p] = await myProfile(tok)
  assert.equal(p.account_id, accountY)
  const [pX] = await myProfile((await signIn(A)).accessToken)
  assert.equal(pX.account_id, accountX)
})

console.log('\nTenant isolation (RLS, real sessions)')
let contactX
await test('A creates a contact in X', async () => {
  const r = await rest('contacts', {
    token: tokA,
    method: 'POST',
    body: { account_id: accountX, user_id: userA, name: `Paciente ${run}`, phone: `5511999${run.replace(/\D/g, '').padEnd(6, '0').slice(0, 6)}` },
  })
  assert.equal(r.status, 201, JSON.stringify(r.data))
  contactX = r.data[0].id
})
await test('B (same business) sees it', async () => {
  const r = await rest(`contacts?select=id&id=eq.${contactX}`, { token: tokB })
  assert.equal(r.data.length, 1)
})
await test('C (other business) does not see it', async () => {
  const r = await rest(`contacts?select=id&id=eq.${contactX}`, { token: tokC })
  assert.equal(r.data.length, 0)
  const all = await rest('contacts?select=account_id', { token: tokC })
  assert.ok(all.data.every((c) => c.account_id === accountY))
})
await test("C cannot read X's account, conversations or WhatsApp config", async () => {
  assert.equal((await rest(`accounts?select=id&id=eq.${accountX}`, { token: tokC })).data.length, 0)
  assert.equal((await rest(`conversations?select=id&account_id=eq.${accountX}`, { token: tokC })).data.length, 0)
  assert.equal((await rest(`whatsapp_config?select=id&account_id=eq.${accountX}`, { token: tokC })).data.length, 0)
})
await test('C cannot write into X (insert with X account_id is refused)', async () => {
  const r = await rest('contacts', {
    token: tokC,
    method: 'POST',
    body: { account_id: accountX, user_id: userA, name: 'intruder', phone: '5511888887777' },
  })
  assert.ok(r.status >= 400, `expected RLS rejection, got ${r.status}`)
})
await test('C cannot update or delete X data', async () => {
  const up = await rest(`contacts?id=eq.${contactX}`, { token: tokC, method: 'PATCH', body: { name: 'hacked' } })
  assert.equal(up.data?.length ?? 0, 0)
  const del = await rest(`contacts?id=eq.${contactX}`, { token: tokC, method: 'DELETE' })
  assert.equal(del.data?.length ?? 0, 0)
  const still = await rest(`contacts?select=name&id=eq.${contactX}`, { token: tokA })
  assert.equal(still.data[0].name, `Paciente ${run}`)
})
await test('mapping tables are invisible to signed-in users', async () => {
  for (const table of ['quaddro_business_links', 'quaddro_member_links', 'quaddro_sso_nonces']) {
    const r = await rest(`${table}?select=*`, { token: tokA })
    assert.ok(r.status >= 400 || r.data.length === 0, `${table} leaked`)
  }
})
await test('provisioning RPCs are not callable by signed-in users', async () => {
  const r = await rest('rpc/quaddro_provision_member', {
    token: tokC,
    method: 'POST',
    body: { p_business_id: bizX.businessId, p_business_name: 'x', p_owner_user_id: randomUUID(), p_member_id: 'x', p_user_id: randomUUID(), p_role: 'admin', p_full_name: 'x', p_email: 'x' },
  })
  assert.ok(r.status === 401 || r.status === 403 || r.status === 404, `got ${r.status}`)
})
await test('team-management APIs are closed in Quaddro mode', async () => {
  const res = await fetch(new URL('/api/account/invitations', BASE), { method: 'POST' })
  assert.equal(res.status, 403)
})
await test('password login page bounces into SSO', async () => {
  const res = await fetch(new URL('/login', BASE), { redirect: 'manual' })
  assert.ok([307, 308].includes(res.status))
  assert.match(res.headers.get('location'), /\/api\/sso\/quaddro\/start\?next=%2Finbox$/)
})
await test('unauthenticated deep link bounces into SSO and remembers the page', async () => {
  const res = await fetch(new URL('/contacts', BASE), { redirect: 'manual' })
  assert.match(res.headers.get('location'), /\/api\/sso\/quaddro\/start\?next=%2Fcontacts$/)
})

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
