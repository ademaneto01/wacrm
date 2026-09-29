import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { QuaddroMark } from "@/components/brand/quaddro-logo";
import { QUADDRO_WHATSAPP_PATH, isQuaddroMode, quaddroUrl } from "@/lib/quaddro/config";
import { isSsoFailure } from "@/lib/quaddro/sso-flow";

// Where every failed Quaddro SSO attempt lands (/api/sso/quaddro/*).
// Plain-language message + a way back into the flow; never a password
// form, since Quaddro users have no WACRM password.

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

export default async function QuaddroSsoErrorPage({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason: raw } = await searchParams;
  const reason = isSsoFailure(raw) ? raw : "unavailable";
  const t = await getTranslations("QuaddroSso");
  const retryHref = isQuaddroMode() ? quaddroUrl(QUADDRO_WHATSAPP_PATH) : "/";

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm rounded-xl border border-border bg-card p-6 text-center shadow-sm">
        <div className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <QuaddroMark className="h-6 w-6" />
        </div>
        <h1 className="text-base font-semibold text-foreground">{t("errorTitle")}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{t(`errors.${reason}`)}</p>
        <a
          href={retryHref}
          className="mt-6 inline-flex h-9 w-full items-center justify-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary-hover"
        >
          {t("retry")}
        </a>
      </div>
    </main>
  );
}
