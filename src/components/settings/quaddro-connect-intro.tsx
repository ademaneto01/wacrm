'use client';

import { useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';
import { QuaddroMark } from '@/components/brand/quaddro-logo';
import { useAuth } from '@/hooks/use-auth';
import { createClient } from '@/lib/supabase/client';

/**
 * First-run welcome above the WhatsApp connection form when the app
 * runs as the Quaddro WhatsApp module — where a freshly provisioned
 * Quaddro business lands (src/lib/quaddro/sso-flow.ts). Hidden once a
 * number is connected.
 */
export function QuaddroConnectIntro() {
  const t = useTranslations('QuaddroSso');
  const { account } = useAuth();
  const [connected, setConnected] = useState<boolean | null>(null);

  useEffect(() => {
    if (!account?.id) return;
    let cancelled = false;
    createClient()
      .from('whatsapp_config')
      .select('status')
      .eq('account_id', account.id)
      .maybeSingle()
      .then(({ data }) => {
        if (!cancelled) setConnected(data?.status === 'connected');
      });
    return () => {
      cancelled = true;
    };
  }, [account?.id]);

  if (connected !== false) return null;

  return (
    <div className="mb-4 flex items-start gap-4 rounded-xl border border-primary-soft-2 bg-primary-soft p-5">
      <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <QuaddroMark className="size-6" />
      </span>
      <div className="min-w-0">
        <h2 className="text-base font-semibold text-foreground">{t('connectTitle')}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{t('connectDescription')}</p>
      </div>
    </div>
  );
}
