import type { SVGProps } from "react";

// Quaddro brand mark, copied from the Quaddro panel
// (web-pro-app app/assets/icons/Quaddro.tsx). Used when the app runs as
// the Quaddro WhatsApp module (see src/lib/quaddro/config.ts).

export const QUADDRO_MARK_PATH =
  "M23.551 45.564l6.882 3.277L38.71 31.91a3.72 3.72 0 013.342-2.084h19.164c2.745 0 4.544 2.866 3.346 5.33l-3.43 7.05a3.707 3.707 0 001.774 4.981l7.037 3.277 4.916-9.405C80.347 30.56 72.712 18 60.846 18H41.942a14.877 14.877 0 00-13.446 8.493l-6.704 14.136a3.706 3.706 0 001.76 4.935zm53.74 8.64l-6.882-3.276-8.278 16.93a3.72 3.72 0 01-3.342 2.084H39.625c-2.745 0-4.544-2.866-3.346-5.33l3.43-7.05a3.706 3.706 0 00-1.774-4.981l-7.037-3.277-4.916 9.406c-5.486 10.497 2.148 23.058 14.014 23.058H58.9c5.75 0 10.986-3.306 13.446-8.492L79.05 59.14a3.707 3.707 0 00-1.76-4.936z";

/** Quaddro brand blue (`brand-base` in @quaddro/theme). */
export const QUADDRO_BLUE = "#002BFF";

export function QuaddroMark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 100 100" fill="currentColor" aria-hidden="true" {...props}>
      <path fillRule="evenodd" clipRule="evenodd" d={QUADDRO_MARK_PATH} />
    </svg>
  );
}
