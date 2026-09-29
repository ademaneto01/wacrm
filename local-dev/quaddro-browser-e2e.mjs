#!/usr/bin/env node
// ============================================================
// Browser end-to-end check: Quaddro login → sidebar "WhatsApp" →
// automatic sign-in to WACRM, inside the right business workspace.
//
// Needs, all LOCAL: Quaddro API (:3333) + web-pro-app (:3001) with
// WACRM_URL/WACRM_SSO_SECRET, the dev seed (quaddro docs/wacrm/dev-seed.sql),
// and WACRM on :3100 in Quaddro mode. Playwright is not a dependency of
// either repo — install it anywhere and point PLAYWRIGHT_DIR at it:
//
//   mkdir -p /tmp/pw && (cd /tmp/pw && npm i playwright@1 && npx playwright install chromium)
//   PLAYWRIGHT_DIR=/tmp/pw node local-dev/quaddro-browser-e2e.mjs [screenshotDir]
// ============================================================

import assert from 'node:assert/strict'
import { mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(
  process.env.PLAYWRIGHT_DIR ? `${process.env.PLAYWRIGHT_DIR.replace(/\/$/, '')}/` : import.meta.url,
)
const { chromium } = require('playwright')

const QUADDRO = process.env.QUADDRO_URL ?? 'http://localhost:3001'
const WACRM = process.env.WACRM_URL ?? 'http://localhost:3100'
const SHOTS = process.argv[2] ?? null
const PASSWORD = 'wacrm-dev-123'
const SECURITY_LABEL = 'Login e segurança'
const MEMBERS_LABEL = 'Membros da equipe'
if (SHOTS) mkdirSync(SHOTS, { recursive: true })

const USERS = [
  { key: 'ana', email: 'ana@wacrm-dev.test', business: 'Clínica Sorriso (dev)', role: 'Admin' },
  { key: 'bruno', email: 'bruno@wacrm-dev.test', business: 'Clínica Sorriso (dev)', role: 'Agente' },
  { key: 'carla', email: 'carla@wacrm-dev.test', business: 'Studio Bem-Estar (dev)', role: 'Admin' },
]

let passed = 0
let failed = 0
async function step(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  ✓ ${name}`)
  } catch (err) {
    failed++
    console.log(`  ✗ ${name}\n      ${String(err?.message ?? err).split('\n')[0]}`)
  }
}
const shot = async (page, name) => {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: false })
}

const browser = await chromium.launch()

for (const user of USERS) {
  console.log(`\n${user.email} (${user.business})`)
  const context = await browser.newContext({ viewport: { width: 1366, height: 820 }, locale: 'pt-BR' })
  const page = await context.newPage()

  await step('logs into Quaddro with e-mail and password', async () => {
    await page.goto(`${QUADDRO}/login`)
    await page.fill('input[name="email"]', user.email)
    await page.fill('input[name="password"]', PASSWORD)
    await page.getByRole('button', { name: 'Entrar', exact: true }).click()
    await page.waitForURL((url) => !url.pathname.startsWith('/login') && !url.pathname.startsWith('/onboarding'), {
      timeout: 60_000,
    })
  })

  await step('sees "WhatsApp" in the Quaddro sidebar', async () => {
    const link = page.locator('nav[aria-label="Menu lateral"] a[href="/whatsapp"]')
    await link.waitFor({ timeout: 30_000 })
    assert.equal((await link.innerText()).trim(), 'WhatsApp')
    await page.waitForLoadState('networkidle')
    await shot(page, `${user.key}-01-quaddro-sidebar`)
  })

  await step('clicking it lands in WACRM signed in, no second login', async () => {
    // Quaddro may show marketing/onboarding modals over the page on first
    // load; close them the way a user would.
    await page.keyboard.press('Escape').catch(() => {})
    await page.locator('nav[aria-label="Menu lateral"] a[href="/whatsapp"]').click({ timeout: 15_000 })
    await page.waitForURL((url) => url.origin === WACRM, { timeout: 60_000 })
    await page.waitForLoadState('networkidle')
    const url = new URL(page.url())
    assert.ok(!url.pathname.startsWith('/sso/quaddro/error'), `SSO error page: ${url.search}`)
    assert.ok(!url.pathname.startsWith('/login'), 'bounced to a password login')
    assert.equal(`${url.pathname}${url.search}`, '/settings?tab=whatsapp')
  })

  await step('shows the Quaddro-branded connect screen for the right business', async () => {
    await page.getByText('Conecte seu WhatsApp').waitFor({ timeout: 30_000 })
    await page.getByText(user.business).first().waitFor({ timeout: 15_000 })
    const title = await page.title()
    assert.match(title, /Quaddro/)
    const theme = await page.evaluate(() => [document.documentElement.dataset.theme, document.documentElement.dataset.mode])
    assert.deepEqual(theme, ['quaddro', 'light'])
    await shot(page, `${user.key}-02-wacrm-connect`)
  })

  await step('password/security and team settings are hidden', async () => {
    const rail = page.locator('nav[aria-label]').filter({ has: page.getByRole('button', { name: 'WhatsApp' }) })
    await rail.waitFor({ timeout: 15_000 })
    assert.equal(await rail.getByRole('button', { name: SECURITY_LABEL }).count(), 0)
    assert.equal(await rail.getByRole('button', { name: MEMBERS_LABEL }).count(), 0)
  })

  await step('"Voltar para a Quaddro" points back to the panel', async () => {
    const back = page.getByRole('link', { name: 'Voltar para a Quaddro' })
    assert.equal(await back.getAttribute('href'), QUADDRO)
  })

  await step('inbox opens', async () => {
    await page.goto(`${WACRM}/inbox`)
    await page.waitForLoadState('networkidle')
    assert.equal(new URL(page.url()).pathname, '/inbox')
    await shot(page, `${user.key}-03-wacrm-inbox`)
  })

  await step('an expired WACRM session re-authenticates silently via Quaddro', async () => {
    const wacrmCookies = (await context.cookies(WACRM)).filter((c) => c.name.startsWith('sb-'))
    await context.clearCookies({ domain: 'localhost', name: /^sb-/ })
    assert.ok(wacrmCookies.length > 0)
    await page.goto(`${WACRM}/contacts`)
    await page.waitForURL((url) => url.origin === WACRM && url.pathname === '/contacts', { timeout: 60_000 })
    await page.waitForLoadState('networkidle')
    await page.getByText(user.business).first().waitFor({ timeout: 15_000 })
  })

  await context.close()
}

await browser.close()
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
