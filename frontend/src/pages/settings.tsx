import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useEffect, useState, type FormEvent } from "react";

import { api, setAccessToken, unwrap } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { useToast } from "@/components/toast";
import { Badge, Button, Card, CardHeader, ErrorNote, Field, Input, Spinner } from "@/components/ui";

export function SettingsPage() {
  const { me } = useAuth();

  if (me?.kind === "api_key") {
    return (
      <>
        <PageHeader title="Account" />
        <Card className="p-4 text-sm text-muted">Signed in with an API key; there is no account to manage here.</Card>
      </>
    );
  }

  return (
    <>
      <PageHeader title="Account" description={`${me?.username ?? ""} · ${me?.role ?? ""}`} />
      <div className="grid gap-4 lg:grid-cols-2">
        <TwoFactor />
        <ChangePassword />
        <Sessions />
      </div>
    </>
  );
}

function TwoFactor() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [enrollment, setEnrollment] = useState<{ secret: string; uri: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");

  const me = useQuery({ queryKey: ["me"], queryFn: async () => unwrap(await api.GET("/auth/me")) });
  const enabled = me.data?.totp_enabled === true;

  useEffect(() => {
    if (!enrollment) {
      setQr(null);
      return;
    }
    let cancelled = false;
    QRCode.toDataURL(enrollment.uri, { margin: 1, width: 220 })
      .then((data) => !cancelled && setQr(data))
      .catch(() => !cancelled && setQr(null));
    return () => {
      cancelled = true;
    };
  }, [enrollment]);

  const begin = useMutation({
    mutationFn: async () => unwrap(await api.POST("/auth/totp/enroll")),
    onSuccess: (data) => {
      if (data.secret && data.uri) setEnrollment({ secret: data.secret, uri: data.uri });
    },
    onError: toast.error,
  });

  const confirm = useMutation({
    mutationFn: async () => {
      const result = await api.POST("/auth/totp/confirm", { body: { code: code.replace(/\s+/g, "") } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Two-factor authentication is on");
      setEnrollment(null);
      setCode("");
      void queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: toast.error,
  });

  const disable = useMutation({
    mutationFn: async () => {
      const result = await api.POST("/auth/totp/disable", { body: { password } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Two-factor authentication is off");
      setPassword("");
      void queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    onError: toast.error,
  });

  return (
    <Card>
      <CardHeader
        title="Two-factor authentication"
        description="A code from an authenticator app on every sign-in."
        actions={me.data && (enabled ? <Badge tone="ok">on</Badge> : <Badge tone="warn">off</Badge>)}
      />
      <div className="p-4">
        {me.isPending ? (
          <Spinner />
        ) : me.isError ? (
          <ErrorNote error={me.error} />
        ) : enabled ? (
          <form
            className="flex flex-col gap-3"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              disable.mutate();
            }}
          >
            <p className="text-sm text-muted">
              Turning it off needs your password, so a session left open on somebody else's screen is not enough.
            </p>
            <Field label="Password" htmlFor="totp-off-password">
              <Input
                id="totp-off-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Field>
            <Button type="submit" variant="danger" loading={disable.isPending} className="self-start">
              Turn off
            </Button>
          </form>
        ) : enrollment ? (
          <form
            className="flex flex-col gap-3"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              confirm.mutate();
            }}
          >
            <p className="text-sm text-muted">Scan this with the authenticator app, then enter the code it shows.</p>
            {qr && (
              <div className="self-start rounded-md border border-border bg-white p-2">
                <img src={qr} alt="QR code for the authenticator app" width={200} height={200} />
              </div>
            )}
            <p className="text-xs text-muted">
              Or enter this key by hand: <code className="break-all">{enrollment.secret}</code>
            </p>
            <Field label="Code" htmlFor="totp-code">
              <Input
                id="totp-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
                autoFocus
              />
            </Field>
            <div className="flex gap-2">
              <Button type="submit" variant="primary" loading={confirm.isPending}>
                Confirm
              </Button>
              <Button type="button" onClick={() => setEnrollment(null)}>
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <Button variant="primary" onClick={() => begin.mutate()} loading={begin.isPending}>
            Set up
          </Button>
        )}
      </div>
    </Card>
  );
}

function ChangePassword() {
  const toast = useToast();
  const { logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);

  const change = useMutation({
    mutationFn: async () => {
      if (next !== again) throw new Error("The new passwords do not match.");
      const result = await api.POST("/auth/password", { body: { current_password: current, new_password: next } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Password changed. Every session was signed out; sign in again.");
      // The panel revoked every session including this one, so the local one ends too.
      setAccessToken(null);
      void logout();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <Card>
      <CardHeader title="Password" description="Changing it signs out every session, this one included." />
      <form
        className="flex flex-col gap-3 p-4"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          setError(null);
          change.mutate();
        }}
      >
        <Field label="Current password" htmlFor="pw-current">
          <Input
            id="pw-current"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
          />
        </Field>
        <Field label="New password" htmlFor="pw-new" hint="At least 12 characters. Length matters more than symbols.">
          <Input
            id="pw-new"
            type="password"
            autoComplete="new-password"
            minLength={12}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
          />
        </Field>
        <Field label="New password again" htmlFor="pw-again">
          <Input
            id="pw-again"
            type="password"
            autoComplete="new-password"
            value={again}
            onChange={(e) => setAgain(e.target.value)}
            required
          />
        </Field>
        {error && (
          <p className="text-sm text-bad" role="alert">
            {error}
          </p>
        )}
        <Button type="submit" variant="primary" loading={change.isPending} className="self-start">
          Change password
        </Button>
      </form>
    </Card>
  );
}

function Sessions() {
  const toast = useToast();
  const { logout } = useAuth();

  const everywhere = useMutation({
    mutationFn: async () => {
      const result = await api.POST("/auth/logout-all");
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Signed out everywhere");
      void logout();
    },
    onError: toast.error,
  });

  return (
    <Card>
      <CardHeader title="Sessions" description="For when a laptop is lost or a browser was left signed in." />
      <div className="p-4">
        <Button variant="danger" onClick={() => everywhere.mutate()} loading={everywhere.isPending}>
          Sign out everywhere
        </Button>
      </div>
    </Card>
  );
}
