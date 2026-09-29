#!/usr/bin/env node
// ============================================================
// End-to-end check: Quaddro patients → WACRM contacts.
//
// Needs, all LOCAL:
//   - WACRM on :3100 (npx next dev -p 3100) + the local-dev Supabase;
//   - a Quaddro API whose database is the LOCAL Quaddro Supabase, with
//     WACRM_API_SECRET = QUADDRO_API_SECRET, at QUADDRO_API_URL;
//   - the Quaddro dev seed (quaddro/docs/wacrm/dev-seed.sql), which
//     creates the two businesses, their members and their patients.
//
// Asserts, over real HTTP and real Postgres/RLS:
//   Quaddro API:  listPatients returns only the token's business,
//                 without archived patients or PII beyond name/phone;
//                 forged / SSO-audience / missing tokens are refused.
//   WACRM:        sign-in syncs the patients; the contacts of each
//                 business are exactly its patients with a mobile
//                 number; the sync endpoint is throttled and cannot be
//                 pointed at another business; name/phone of a patient
//                 are read-only for the user; RLS keeps businesses apart.
//
// Usage (from the wacrm repo root):
//   node --env-file=.env.development.local local-dev/quaddro-patients-e2e.mjs [http://localhost:3100]
//
// DEVELOPMENT ONLY. Never point it at a shared or production stack.
// ============================================================

import { createHmac, randomUUID } from 'node:crypto'
import assert from 'node:assert/strict'

const BASE = process.argv[2] ?? 'http://localhost:3100'
const SSO_SECRET = process.env.QUADDRO_SSO_SECRET
const API_URL = (process.env.QUADDRO_API_URL ?? '').replace(/\/+$/, '')
const API_SECRET = process.env.QUADDRO_API_SECRET
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY
if (!SSO_SECRET || !API_URL || !API_SECRET || !SUPABASE_URL || !ANON || !SERVICE) {
  console.error('Missing env: run with --env-file=.env.development.local (needs QUADDRO_API_URL/SECRET)')
  process.exit(2)
}
for (const url of [SUPABASE_URL, API_URL, BASE]) {
  if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(url)) {
    console.error(`Refusing to run against a non-local service (${url}).`)
    process.exit(2)
  }
}

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

const b64 = (v) => Buffer.from(v).toString('base64url')
function sign(claims, secret) {
  const input = `${b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64(JSON.stringify(claims))}`
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`
}
const now = () => Math.floor(Date.now() / 1000)

// ---------- fixtures: quaddro/docs/wacrm/dev-seed.sql ----------
const CLINICA = 'a0000000-0000-4000-8000-00000000000a'
const STUDIO = 'a0000000-0000-4000-8000-00000000000b'
const ANA = { memberId: 'a0000000-0000-4000-8000-0000000000a1', businessId: CLINICA, businessName: 'Clínica Sorriso (dev)', name: 'Ana Dev', email: 'ana@wacrm-dev.test', role: 'owner' }
const CARLA = { memberId: 'a0000000-0000-4000-8000-0000000000b1', businessId: STUDIO, businessName: 'Studio Bem-Estar (dev)', name: 'Carla Dev', email: 'carla@wacrm-dev.test', role: 'owner' }
const MARIA = 'a0000000-0000-4000-8000-0000000000d1'
const JOAO = 'a0000000-0000-4000-8000-0000000000d2'
const ARQUIVADO = 'a0000000-0000-4000-8000-0000000000d3'
const SEM_CELULAR = 'a0000000-0000-4000-8000-0000000000d4'
const CARLOS = 'a0000000-0000-4000-8000-0000000000d5'

// ---------- Quaddro API ----------
function patientsToken(businessId, overrides = {}, secret = API_SECRET) {
  const t = now()
  return sign({ iss: 'wacrm', aud: 'quaddro', scope: 'patients:read', sub: businessId, iat: t, exp: t + 60, jti: randomUUID(), ...overrides }, secret)
}
async function listPatients(token) {
  const res = await fetch(`${API_URL}/operations/integrations/wacrm/listPatients`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ data: token === undefined ? {} : { token } }),
  })
  const body = await res.json()
  return body.json ?? body
}

// ---------- WACRM sign-in (plays the Quaddro panel, like quaddro-sso-e2e.mjs) ----------
const setCookies = (res) => res.headers.getSetCookie?.() ?? []
const cookiePairs = (list) => list.map((c) => c.split(';')[0]).filter((c) => !c.endsWith('='))

async function signIn(who) {
  const startRes = await fetch(new URL('/api/sso/quaddro/start', BASE), { redirect: 'manual' })
  const state = new URL(startRes.headers.get('location')).searchParams.get('state')
  const t = now()
  const token = sign({ iss: 'quaddro', aud: 'wacrm', iat: t, exp: t + 60, jti: randomUUID(), state, sub: who.memberId, bid: who.businessId, bname: who.businessName, name: who.name, email: who.email, role: who.role }, SSO_SECRET)
  const res = await fetch(new URL('/api/sso/quaddro/callback', BASE), {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookiePairs(setCookies(startRes)).join('; ') },
    body: new URLSearchParams({ token }),
  })
  assert.equal(res.status, 303)
  assert.ok(!res.headers.get('location').startsWith('/sso/quaddro/error'), `sign-in failed → ${res.headers.get('location')}`)
  const auth = cookiePairs(setCookies(res)).filter((c) => /^sb-[^=]+-auth-token(\.\d+)?=/.test(c))
  const raw0 = decodeURIComponent(auth.slice().sort().map((c) => c.slice(c.indexOf('=') + 1)).join(''))
  const raw = raw0.startsWith('base64-') ? Buffer.from(raw0.slice(7), 'base64url').toString('utf8') : raw0
  return { cookie: auth.join('; '), accessToken: JSON.parse(raw).access_token }
}

async function syncNow(session, body = { force: true }) {
  const res = await fetch(new URL('/api/quaddro/contacts/sync', BASE), {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: session.cookie },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

async function rest(path, { token, method = 'GET', body, service = false } = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: service ? SERVICE : ANON,
      authorization: `Bearer ${service ? SERVICE : token}`,
      'content-type': 'application/json',
      prefer: 'return=representation',
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  return { status: res.status, data: text ? JSON.parse(text) : null }
}
const accountOf = async (businessId) =>
  (await rest(`quaddro_business_links?select=account_id&quaddro_business_id=eq.${businessId}`, { service: true })).data[0]?.account_id
const resetThrottle = async (businessId) =>
  rest(`quaddro_business_links?quaddro_business_id=eq.${businessId}`, { method: 'PATCH', body: { patients_synced_at: null }, service: true })
// What the Contacts page queries in Quaddro mode, as the signed-in user (RLS applies).
const patientContacts = async (token) =>
  (await rest('contacts?select=id,name,phone,quaddro_client_id,account_id&quaddro_client_id=not.is.null&order=name', { token })).data

console.log(`Quaddro patients e2e — WACRM ${BASE}, Quaddro API ${API_URL}\n`)

console.log('Quaddro API: integrations/wacrm/listPatients')
await test('lists only the token business active patients, name + phone only', async () => {
  const { result } = await listPatients(patientsToken(CLINICA))
  const byId = Object.fromEntries(result.data.map((p) => [p.id, p]))
  assert.deepEqual(Object.keys(byId).sort(), [MARIA, JOAO, SEM_CELULAR].sort())
  assert.deepEqual(byId[JOAO], { id: JOAO, name: 'João Pereira', phone: '5511990000102' })
  assert.equal(byId[SEM_CELULAR].phone, '')
  assert.ok(!(ARQUIVADO in byId), 'archived patient leaked')
  assert.ok(!(CARLOS in byId), 'other business patient leaked')
  for (const p of result.data) assert.deepEqual(Object.keys(p).sort(), ['id', 'name', 'phone'])
})
await test('the same patient carries each business own name', async () => {
  const { result } = await listPatients(patientsToken(STUDIO))
  assert.deepEqual(result.data.map((p) => p.name).sort(), ['Carlos Studio', 'Maria (Studio)'])
})
await test('token signed with another secret → 401', async () => {
  assert.equal((await listPatients(patientsToken(CLINICA, {}, 'y'.repeat(48)))).error?.code, 401)
})
await test('SSO handoff token (aud wacrm) is not accepted here → 401', async () => {
  const t = now()
  const sso = sign({ iss: 'quaddro', aud: 'wacrm', sub: CLINICA, iat: t, exp: t + 60 }, API_SECRET)
  assert.equal((await listPatients(sso)).error?.code, 401)
})
await test('expired token → 401', async () => {
  assert.equal((await listPatients(patientsToken(CLINICA, { iat: now() - 600, exp: now() - 540 }))).error?.code, 401)
})
await test('missing token → 400', async () => {
  assert.equal((await listPatients(undefined)).error?.code, 400)
})

console.log('\nWACRM: contacts = patients of the signed-in business')
const ana = await signIn(ANA)
const carla = await signIn(CARLA)
// the sign-in schedules a sync after the response; give it a moment
await new Promise((r) => setTimeout(r, 2500))

await test('sign-in synced the Clínica patients with a mobile number', async () => {
  const rows = await patientContacts(ana.accessToken)
  assert.deepEqual(rows.map((c) => [c.quaddro_client_id, c.name, c.phone]), [
    [JOAO, 'João Pereira', '5511990000102'],
    [MARIA, 'Maria Souza', '5511990000101'],
  ])
})
await test('the Studio sees only its own patients (RLS), with its own names', async () => {
  const rows = await patientContacts(carla.accessToken)
  assert.deepEqual(rows.map((c) => c.name), ['Carlos Studio', 'Maria (Studio)'])
  const studioAccount = await accountOf(STUDIO)
  assert.ok(rows.every((c) => c.account_id === studioAccount))
})
await test('a user cannot read the other business contacts even by id', async () => {
  const clinicaIds = (await patientContacts(ana.accessToken)).map((c) => c.id)
  const { data } = await rest(`contacts?select=id&id=in.(${clinicaIds.join(',')})`, { token: carla.accessToken })
  assert.deepEqual(data, [])
})
await test('sync right after sign-in is throttled', async () => {
  const r = await syncNow(ana)
  assert.equal(r.status, 200)
  assert.deepEqual(r.body, { status: 'skipped', reason: 'recent' })
})
await test('a forced sync after the throttle is idempotent', async () => {
  await resetThrottle(CLINICA)
  const r = await syncNow(ana)
  assert.equal(r.body.status, 'synced')
  assert.deepEqual(
    { ...r.body.counts, patients: undefined },
    { patients: undefined, inserted: 0, linked: 0, renamed: 0, rephoned: 0, unlinked: 0 },
  )
})
await test('the body cannot point the sync at another business', async () => {
  await resetThrottle(CLINICA)
  const r = await syncNow(ana, { force: true, businessId: STUDIO, accountId: await accountOf(STUDIO) })
  assert.equal(r.body.status, 'synced')
  assert.deepEqual((await patientContacts(ana.accessToken)).map((c) => c.name), ['João Pereira', 'Maria Souza'])
})
await test('sync without a session → 401', async () => {
  const res = await fetch(new URL('/api/quaddro/contacts/sync', BASE), { method: 'POST' })
  assert.equal(res.status, 401)
})
await test('name and phone of a patient are read-only for the user; other fields save', async () => {
  const [joao] = (await patientContacts(ana.accessToken)).filter((c) => c.quaddro_client_id === JOAO)
  const { status } = await rest(`contacts?id=eq.${joao.id}`, {
    token: ana.accessToken,
    method: 'PATCH',
    body: { name: 'Renomeado no WACRM', phone: '5511900009999', quaddro_client_id: null, company: 'Empresa X' },
  })
  assert.equal(status, 200)
  const { data } = await rest(`contacts?select=name,phone,quaddro_client_id,company&id=eq.${joao.id}`, { token: ana.accessToken })
  assert.deepEqual(data[0], { name: 'João Pereira', phone: '5511990000102', quaddro_client_id: JOAO, company: 'Empresa X' })
  await rest(`contacts?id=eq.${joao.id}`, { method: 'PATCH', body: { company: null }, service: true })
})
await test('a user cannot forge a patient link on insert', async () => {
  const account = await accountOf(CLINICA)
  const { data } = await rest('contacts', {
    token: ana.accessToken,
    method: 'POST',
    body: { account_id: account, user_id: JSON.parse(Buffer.from(ana.accessToken.split('.')[1], 'base64url')).sub, phone: '5511977770000', name: 'Forjado', quaddro_client_id: CARLOS },
  })
  assert.equal(data[0].quaddro_client_id, null)
  await rest(`contacts?id=eq.${data[0].id}`, { method: 'DELETE', service: true })
})

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
