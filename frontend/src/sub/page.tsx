import { Check, Copy, Download, QrCode, ShieldAlert } from "lucide-react";
import QRCode from "qrcode";
import { useEffect, useMemo, useState } from "react";

// Type-only: the admin API client itself is not part of this page's bundle.
import type { Schemas } from "@/api/client";
import { Badge, Button, Card, CardHeader, Input, Spinner, UsageMeter, type Tone } from "@/components/ui";
import { useCopy } from "@/lib/hooks";
import { formatBytes, formatDate, formatRelative, usageRatio } from "@/lib/utils";
import { clientApps, downloadFormats } from "@/sub/clients";
import { dictionaries, pickLanguage } from "@/sub/i18n";

/** What GET /sub/{token}/info returns, generated from api/openapi.yaml. */
type PublicSubscription = Schemas["PublicSubscription"];

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; data: PublicSubscription }
  | { kind: "error"; reason: "notFound" | "rateLimited" | "failed" };

const statusTone: Record<PublicSubscription["status"], Tone> = {
  active: "ok",
  limited: "warn",
  expired: "bad",
  disabled: "idle",
};

/** The token is the last path segment of /sub/{token}. */
function tokenFromPath(pathname: string): string | null {
  const match = /^\/sub\/([^/]+)\/?$/.exec(pathname);
  return match?.[1] ?? null;
}

export function SubscriptionPage() {
  const language = useMemo(() => pickLanguage(navigator.languages ?? [navigator.language]), []);
  const t = dictionaries[language];
  const token = tokenFromPath(window.location.pathname);
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  useEffect(() => {
    if (!token) {
      setState({ kind: "error", reason: "notFound" });
      return;
    }
    const controller = new AbortController();
    fetch(`/sub/${encodeURIComponent(token)}/info`, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
      // The token is in the URL already; nothing else about this browser needs to go along.
      credentials: "omit",
      referrerPolicy: "no-referrer",
    })
      .then(async (response) => {
        if (response.status === 404) return setState({ kind: "error", reason: "notFound" });
        if (response.status === 429) return setState({ kind: "error", reason: "rateLimited" });
        if (!response.ok) return setState({ kind: "error", reason: "failed" });
        setState({ kind: "ready", data: (await response.json()) as PublicSubscription });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          console.error(error);
          setState({ kind: "error", reason: "failed" });
        }
      });
    return () => controller.abort();
  }, [token]);

  useEffect(() => {
    if (state.kind === "ready" && state.data.profile_title) document.title = state.data.profile_title;
  }, [state]);

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-2xl flex-col gap-4 px-4 py-6 sm:py-10">
      {state.kind === "loading" && <Spinner label={t.loading} />}
      {state.kind === "error" && (
        <Card className="flex items-start gap-3 p-5" role="alert">
          <ShieldAlert className="mt-0.5 size-5 shrink-0 text-bad" aria-hidden />
          <p className="text-sm">{t[state.reason]}</p>
        </Card>
      )}
      {state.kind === "ready" && token && <Subscription data={state.data} token={token} t={t} />}
    </main>
  );
}

type Dictionary = (typeof dictionaries)["en"];

function Subscription({ data, token, t }: { data: PublicSubscription; token: string; t: Dictionary }) {
  const subscriptionUrl = `${window.location.origin}/sub/${token}`;
  const title = data.profile_title || t.title;
  const active = data.status === "active";
  const ratio = usageRatio(data.traffic_used, data.traffic_limit);

  return (
    <>
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs tracking-wide text-muted uppercase">{title}</p>
          <h1 className="truncate text-xl font-semibold">{data.username}</h1>
        </div>
        <Badge tone={statusTone[data.status]}>{t.status[data.status]}</Badge>
      </header>

      {!active && (
        <div className="rounded-md border border-warn/30 bg-warn-soft px-4 py-3 text-sm text-warn" role="status">
          {t.inactive[data.status as Exclude<PublicSubscription["status"], "active">]}
        </div>
      )}

      <Card className="grid gap-4 p-4 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <p className="mb-1 text-xs font-medium text-muted">{t.traffic}</p>
          <UsageMeter
            ratio={ratio}
            label={
              data.traffic_limit > 0
                ? t.ofLimit(formatBytes(data.traffic_used), formatBytes(data.traffic_limit))
                : t.unlimited(formatBytes(data.traffic_used))
            }
          />
        </div>
        <dl className="grid gap-3 text-sm">
          <div>
            <dt className="text-xs font-medium text-muted">{t.expires}</dt>
            <dd className="num">
              {data.expires_at ? (
                <>
                  {formatDate(data.expires_at)}{" "}
                  <span className="text-muted">({formatRelative(data.expires_at)})</span>
                </>
              ) : (
                t.never
              )}
            </dd>
          </div>
          {data.reset_strategy !== "never" && (
            <div>
              <dt className="text-xs font-medium text-muted">{t.resets}</dt>
              <dd>{t.reset[data.reset_strategy]}</dd>
            </div>
          )}
        </dl>
      </Card>

      <AddToApp url={subscriptionUrl} title={title} t={t} />

      <Card>
        <CardHeader title={t.downloadTitle} description={t.downloadHint} />
        <div className="flex flex-wrap gap-2 p-4">
          {downloadFormats.map((item) => (
            <Button key={item.format} asChild size="sm">
              <a href={`${subscriptionUrl}?format=${item.format}`} rel="noreferrer">
                <Download className="size-4" aria-hidden />
                {item.label}
              </a>
            </Button>
          ))}
        </div>
      </Card>

      <Servers links={data.links} t={t} />

      <Card className="p-4">
        <h2 className="mb-2 text-sm font-semibold">{t.stepsTitle}</h2>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
          {t.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </Card>
    </>
  );
}

function AddToApp({ url, title, t }: { url: string; title: string; t: Dictionary }) {
  const [copied, copy] = useCopy();
  const [showQr, setShowQr] = useState(false);
  const [qr, setQr] = useState<string | null>(null);

  useEffect(() => {
    if (!showQr || qr) return;
    // A data URL, so the code is drawn here and the link never goes to a QR service.
    QRCode.toDataURL(url, { margin: 1, width: 240, errorCorrectionLevel: "M" })
      .then(setQr)
      .catch((error: unknown) => console.error(error));
  }, [showQr, qr, url]);

  return (
    <Card>
      <CardHeader title={t.addTitle} description={t.addHint} />
      <div className="flex flex-col gap-4 p-4">
        <div className="grid gap-2 sm:grid-cols-2">
          {clientApps.map((app) => (
            <Button key={app.name} asChild variant="primary" className="h-auto justify-start py-2">
              <a href={app.href(url, title)} rel="noreferrer">
                <span className="flex flex-col items-start text-left">
                  <span>{t.openIn(app.name)}</span>
                  <span className="text-xs font-normal opacity-80">{app.platforms}</span>
                </span>
              </a>
            </Button>
          ))}
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="subscription-url" className="text-xs font-medium text-muted">
            {t.link}
          </label>
          <div className="flex gap-2">
            <Input
              id="subscription-url"
              readOnly
              value={url}
              className="font-mono text-xs"
              onFocus={(event) => event.currentTarget.select()}
            />
            <Button onClick={() => void copy("url", url)} aria-live="polite">
              {copied === "url" ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
              {copied === "url" ? t.copied : t.copy}
            </Button>
          </div>
        </div>

        <div>
          <Button variant="ghost" size="sm" onClick={() => setShowQr((value) => !value)} aria-expanded={showQr}>
            <QrCode className="size-4" aria-hidden />
            {showQr ? t.hideQr : t.showQr}
          </Button>
          {showQr && qr && (
            <figure className="mt-3 flex flex-col items-center gap-2">
              {/* White behind the code in both themes: scanners read dark-on-light. */}
              <img src={qr} alt={t.link} width={240} height={240} className="rounded-md bg-white p-2" />
              <figcaption className="text-xs text-muted">{t.qrHint}</figcaption>
            </figure>
          )}
        </div>
      </div>
    </Card>
  );
}

function Servers({ links, t }: { links: PublicSubscription["links"]; t: Dictionary }) {
  const [copied, copy] = useCopy();

  return (
    <Card>
      <details>
        <summary className="cursor-pointer list-none px-4 py-3">
          <span className="text-sm font-semibold">{t.serversTitle}</span>{" "}
          <span className="num text-xs text-muted">({links.length})</span>
          <p className="mt-0.5 text-xs text-muted">{t.serversHint}</p>
        </summary>
        {links.length === 0 ? (
          <p className="border-t border-border px-4 py-6 text-center text-sm text-muted">{t.noServers}</p>
        ) : (
          <ul className="divide-y divide-border border-t border-border">
            {links.map((item, index) => (
              <li key={`${index}-${item.remark}`} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <span className="min-w-0 truncate text-sm">{item.remark}</span>
                <Button size="sm" variant="ghost" onClick={() => void copy(`link-${index}`, item.link)}>
                  {copied === `link-${index}` ? (
                    <Check className="size-4" aria-hidden />
                  ) : (
                    <Copy className="size-4" aria-hidden />
                  )}
                  {copied === `link-${index}` ? t.copied : t.copy}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </details>
    </Card>
  );
}
