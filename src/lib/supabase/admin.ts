import { createClient, type SupabaseClient } from '@supabase/supabase-js'

// Service-role client for server-only code paths that have no user
// session to act as (the Quaddro SSO callback). Bypasses RLS — never
// import this from a client component.
//
// The ai/, automations/ and flows/ modules each keep their own copy of
// this helper; this one is shared for new code.
let _adminClient: SupabaseClient | null = null

export function supabaseAdmin(): SupabaseClient {
  if (!_adminClient) {
    _adminClient = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
      { auth: { autoRefreshToken: false, persistSession: false } }
    )
  }
  return _adminClient
}
