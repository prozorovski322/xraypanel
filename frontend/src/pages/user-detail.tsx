import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Check, Copy, QrCode, RefreshCw, RotateCcw, Trash2 } from "lucide-react";
import QRCode from "qrcode";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { api, unwrap } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { UserStatusBadge } from "@/components/status";
import { useToast } from "@/components/toast";
import { TrafficChart } from "@/components/traffic-chart";
import { Button, Card, CardHeader, Dialog, ErrorNote, Field, Input, Spinner, UsageMeter } from "@/components/ui";
import { useCopy } from "@/lib/hooks";
import { formatBytes, formatDate, formatDateTime, formatRelative, usageRatio } from "@/lib/utils";

export function UserDetailPage() {
  const params = useParams();
  const id = Number(params["id"]);
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [renewing, setRenewing] = useState(false);
  const [confirm, setConfirm] = useState<null | "delete" | "rotate">(null);

  const user = useQuery({
    queryKey: ["users", id],
    queryFn: async () => unwrap(await api.GET("/users/{id}", { params: { path: { id } } })),
    enabled: Number.isFinite(id),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["users"] });

  const setStatus = useMutation({
    mutationFn: async (status: "active" | "disabled") =>
      unwrap(await api.PATCH("/users/{id}", { params: { path: { id } }, body: { status } })),
    onSuccess: (u) => {
      toast.ok(u.status === "disabled" ? "User disabled" : "User enabled");
      void invalidate();
    },
    onError: toast.error,
  });

  const resetTraffic = useMutation({
    mutationFn: async () => unwrap(await api.POST("/users/{id}/reset-traffic", { params: { path: { id } } })),
    onSuccess: () => {
      toast.ok("Traffic reset");
      void invalidate();
    },
    onError: toast.error,
  });

  const rotate = useMutation({
    mutationFn: async () => unwrap(await api.POST("/users/{id}/rotate-credentials", { params: { path: { id } } })),
    onSuccess: () => {
      toast.ok("Credentials rotated. The old subscription link no longer works.");
      setConfirm(null);
      void invalidate();
      void queryClient.invalidateQueries({ queryKey: ["subscription", id] });
    },
    onError: toast.error,
  });

  const remove = useMutation({
    mutationFn: async () => {
      const result = await api.DELETE("/users/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("User deleted");
      setConfirm(null);
      navigate("/users", { replace: true });
      // Only the lists are refreshed. This page's own queries are left alone: invalidating or
      // removing them while the page is still mounted makes it ask the panel for a user that
      // no longer exists. They are garbage-collected once the page is gone.
      void queryClient.invalidateQueries({ queryKey: ["users", "list"] });
      void queryClient.invalidateQueries({ queryKey: ["users", "top"] });
    },
    onError: toast.error,
  });

  if (!Number.isFinite(id)) return <ErrorNote error={new Error("That is not a user id.")} />;
  if (user.isPending) return <Spinner />;
  if (user.isError) return <ErrorNote error={user.error} />;

  const u = user.data;
  const writable = can("users:write");

  return (
    <>
      <Link to="/users" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-text">
        <ArrowLeft className="size-4" /> Users
      </Link>
      <PageHeader
        title={u.username ?? "User"}
        actions={
          writable && (
            <>
              <Button onClick={() => setRenewing(true)}>
                <RefreshCw className="size-4" /> Renew
              </Button>
              <Button onClick={() => resetTraffic.mutate()} loading={resetTraffic.isPending}>
                <RotateCcw className="size-4" /> Reset traffic
              </Button>
              {u.status === "disabled" ? (
                <Button onClick={() => setStatus.mutate("active")} loading={setStatus.isPending}>
                  Enable
                </Button>
              ) : (
                <Button onClick={() => setStatus.mutate("disabled")} loading={setStatus.isPending}>
                  Disable
                </Button>
              )}
              <Button variant="danger" onClick={() => setConfirm("delete")}>
                <Trash2 className="size-4" /> Delete
              </Button>
            </>
          )
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-1">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 text-sm">
            <dt className="text-muted">Status</dt>
            <dd>
              <UserStatusBadge status={u.status} />
            </dd>
            <dt className="text-muted">Traffic</dt>
            <dd>
              <UsageMeter
                ratio={usageRatio(u.traffic_used, u.traffic_limit)}
                label={
                  u.traffic_limit
                    ? `${formatBytes(u.traffic_used)} of ${formatBytes(u.traffic_limit)}`
                    : `${formatBytes(u.traffic_used)} · no limit`
                }
              />
            </dd>
            <dt className="text-muted">Resets</dt>
            <dd className="capitalize">{u.reset_strategy ?? "never"}</dd>
            <dt className="text-muted">Lifetime</dt>
            <dd className="num">{formatBytes(u.traffic_lifetime)}</dd>
            <dt className="text-muted">Expires</dt>
            <dd>{u.expires_at ? formatDateTime(u.expires_at) : "never"}</dd>
            <dt className="text-muted">Last online</dt>
            <dd>{formatRelative(u.online_at)}</dd>
            <dt className="text-muted">Created</dt>
            <dd>{formatDate(u.created_at)}</dd>
            {u.note && (
              <>
                <dt className="text-muted">Note</dt>
                <dd className="break-words">{u.note}</dd>
              </>
            )}
          </dl>
        </Card>

        <div className="lg:col-span-2">
          <Subscription userId={id} onRotate={writable ? () => setConfirm("rotate") : undefined} />
        </div>
      </div>

      <UserTraffic userId={id} />

      <RenewDialog open={renewing} onOpenChange={setRenewing} userId={id} />

      <Dialog
        open={confirm === "delete"}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={`Delete ${u.username}?`}
        description="The user loses access on every node at once, and their traffic history is removed. This cannot be undone."
        footer={
          <>
            <Button onClick={() => setConfirm(null)}>Cancel</Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
              Delete user
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">
          To pause somebody instead, use <strong>Disable</strong>: it keeps their history and can be undone.
        </p>
      </Dialog>

      <Dialog
        open={confirm === "rotate"}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Rotate credentials?"
        description="New UUID, passwords and subscription link. Every client configured with the old ones stops working."
        footer={
          <>
            <Button onClick={() => setConfirm(null)}>Cancel</Button>
            <Button variant="danger" loading={rotate.isPending} onClick={() => rotate.mutate()}>
              Rotate
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">
          Use this when a link has leaked. The user will need the new link from this page.
        </p>
      </Dialog>
    </>
  );
}

function Subscription({ userId, onRotate }: { userId: number; onRotate?: () => void }) {
  const [copied, copy] = useCopy();
  const toast = useToast();
  const [qr, setQr] = useState<string | null>(null);
  const [qrFor, setQrFor] = useState<string | null>(null);

  const sub = useQuery({
    queryKey: ["subscription", userId],
    queryFn: async () => unwrap(await api.GET("/users/{id}/subscription", { params: { path: { id: userId } } })),
  });

  // The link a client is given. Built from this page's origin: the public subscription
  // endpoint is served by the same panel under /sub.
  const url = sub.data?.subscription_token ? `${window.location.origin}/sub/${sub.data.subscription_token}` : null;

  useEffect(() => {
    if (!qrFor) {
      setQr(null);
      return;
    }
    let cancelled = false;
    QRCode.toDataURL(qrFor, { margin: 1, width: 240, errorCorrectionLevel: "M" })
      .then((data) => !cancelled && setQr(data))
      .catch(() => !cancelled && setQr(null));
    return () => {
      cancelled = true;
    };
  }, [qrFor]);

  async function doCopy(key: string, text: string) {
    const ok = await copy(key, text);
    if (!ok) toast.error("Could not copy. Select the text and copy it by hand.");
  }

  return (
    <Card>
      <CardHeader
        title="Subscription"
        description="What the user imports into their client. Treat it like a password."
        actions={
          onRotate && (
            <Button size="sm" onClick={onRotate}>
              Rotate
            </Button>
          )
        }
      />
      {sub.isPending ? (
        <Spinner />
      ) : sub.isError ? (
        <ErrorNote error={sub.error} />
      ) : (
        <div className="flex flex-col gap-3 p-4">
          {url && (
            <div className="flex items-center gap-2">
              <Input readOnly value={url} aria-label="Subscription link" className="font-mono text-xs" />
              <Button
                size="sm"
                onClick={() => void doCopy("url", url)}
                aria-label="Copy subscription link"
                data-testid="copy-subscription"
              >
                {copied === "url" ? <Check className="size-4" /> : <Copy className="size-4" />}
                {copied === "url" ? "Copied" : "Copy"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setQrFor(qrFor === url ? null : url)} aria-label="Show QR code">
                <QrCode className="size-4" />
              </Button>
            </div>
          )}

          {qr && qrFor && (
            <div className="flex flex-col items-center gap-1 self-start rounded-md border border-border bg-white p-2">
              <img src={qr} alt="QR code of the link" width={200} height={200} />
            </div>
          )}

          {(sub.data.links ?? []).length > 0 && (
            <details className="text-sm">
              <summary className="cursor-pointer text-muted">
                Individual links ({(sub.data.links ?? []).length}) — for clients that take one server at a time
              </summary>
              <ul className="mt-2 flex flex-col gap-1.5">
                {(sub.data.links ?? []).map((link, i) => (
                  <li key={i} className="flex items-center gap-2">
                    <code className="min-w-0 flex-1 truncate rounded bg-surface-2 px-2 py-1 text-xs">{link}</code>
                    <Button size="sm" variant="ghost" onClick={() => void doCopy(`link-${i}`, link)} aria-label="Copy link">
                      {copied === `link-${i}` ? <Check className="size-4" /> : <Copy className="size-4" />}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setQrFor(qrFor === link ? null : link)} aria-label="Show QR code">
                      <QrCode className="size-4" />
                    </Button>
                  </li>
                ))}
              </ul>
            </details>
          )}
          {(sub.data.links ?? []).length === 0 && (
            <p className="text-sm text-muted">
              No servers yet: this user is in no group whose inbounds are attached to a node.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

function UserTraffic({ userId }: { userId: number }) {
  const to = new Date().toISOString().slice(0, 10);
  const from = new Date(Date.now() - 29 * 86_400_000).toISOString().slice(0, 10);

  const traffic = useQuery({
    queryKey: ["users", userId, "traffic", from, to],
    queryFn: async () =>
      unwrap(await api.GET("/users/{id}/traffic", { params: { path: { id: userId }, query: { from, to } } })),
  });

  return (
    <Card className="mt-4">
      <CardHeader
        title="Traffic, last 30 days"
        description={
          traffic.data
            ? `${formatBytes((traffic.data.total_uplink ?? 0) + (traffic.data.total_downlink ?? 0))} in total. Days are UTC; today fills in as the daily rollup runs.`
            : undefined
        }
      />
      {traffic.isPending ? (
        <Spinner />
      ) : traffic.isError ? (
        <ErrorNote error={traffic.error} />
      ) : (
        <TrafficChart
          from={from}
          to={to}
          days={(traffic.data.days ?? []).map((d) => ({ day: d.day, uplink: d.uplink, downlink: d.downlink }))}
        />
      )}
    </Card>
  );
}

function RenewDialog({ open, onOpenChange, userId }: { open: boolean; onOpenChange: (open: boolean) => void; userId: number }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [days, setDays] = useState("30");
  const [reset, setReset] = useState(true);

  const renew = useMutation({
    mutationFn: async () => {
      const n = Number(days);
      if (!Number.isFinite(n) || n <= 0) throw new Error("Days must be a positive number.");
      return unwrap(
        await api.POST("/users/{id}/renew", {
          params: { path: { id: userId } },
          body: { extend_by: `${Math.round(n * 24)}h`, reset_traffic: reset },
        }),
      );
    },
    onSuccess: (u) => {
      toast.ok(`Renewed until ${formatDate(u.expires_at)}`);
      onOpenChange(false);
      void queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: toast.error,
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    renew.mutate();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Renew subscription"
      description="Added to the current expiry, or to now if it has already passed. A limited or expired user comes back."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="renew" loading={renew.isPending}>
            Renew
          </Button>
        </>
      }
    >
      <form id="renew" className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Extend by (days)" htmlFor="renew-days">
          <Input id="renew-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} required />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={reset} onChange={(e) => setReset(e.target.checked)} />
          Also reset traffic used
        </label>
      </form>
    </Dialog>
  );
}
