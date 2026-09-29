// ============================================================
// POST /api/quaddro/contacts/sync   body: { force?: boolean }
//
// Pulls the signed-in user's Quaddro business patients into their
// contacts (src/lib/quaddro/patients.ts). The account — and through
// quaddro_business_links the Quaddro business — comes from the
// session only; nothing in the body can point it at another business.
// Throttled per account (60 s automatic, 10 s forced).
// ============================================================

import { NextResponse } from 'next/server'
import { requireRole, toErrorResponse } from '@/lib/auth/account'
import { isQuaddroMode } from '@/lib/quaddro/config'
import { QuaddroPatientsError, syncQuaddroPatients } from '@/lib/quaddro/patients'
import { supabaseAdmin } from '@/lib/supabase/admin'

export const dynamic = 'force-dynamic'

export async function POST(request: Request) {
  if (!isQuaddroMode()) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  try {
    const ctx = await requireRole('viewer')
    const body = (await request.json().catch(() => null)) as { force?: unknown } | null

    const outcome = await syncQuaddroPatients(supabaseAdmin(), ctx.accountId, {
      force: body?.force === true,
    })
    return NextResponse.json(outcome)
  } catch (error) {
    if (error instanceof QuaddroPatientsError) {
      console.error('[quaddro-patients] sync failed:', error.message)
      return NextResponse.json({ error: 'sync_failed' }, { status: 502 })
    }
    return toErrorResponse(error)
  }
}
