// GET /api/sso/quaddro/health — lets the Quaddro panel check, server to
// server, that this deployment is reachable and has SSO configured
// before it sends a user over. Reveals nothing beyond ok / not ok.

import { NextResponse } from 'next/server'
import { isQuaddroMode } from '@/lib/quaddro/config'
import { getSsoSecret } from '@/lib/quaddro/sso-token'
import { supabaseAdmin } from '@/lib/supabase/admin'

export const dynamic = 'force-dynamic'

export async function GET() {
  if (!isQuaddroMode() || !getSsoSecret()) {
    return NextResponse.json({ ok: false }, { status: 503 })
  }
  const { error } = await supabaseAdmin()
    .from('quaddro_business_links')
    .select('account_id', { head: true, count: 'exact' })
    .limit(1)
  if (error) return NextResponse.json({ ok: false }, { status: 503 })
  return NextResponse.json({ ok: true })
}
