import { Activity } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";

import { ApiError } from "@/api/client";
import { useAuth } from "@/auth";
import { Button, Card, Field, Input } from "@/components/ui";

/**
 * Login is two steps on one screen: the password, and then — only for an account with 2FA —
 * the code. The ticket between them lives in component state only; it is useless on its own
 * and expires in minutes.
 */
export function LoginPage() {
  const { status, login, completeMfa } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (status === "authenticated") return <Navigate to={from} replace />;

  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const step = await login(username, password);
      if (step.kind === "mfa") {
        setMfaToken(step.mfaToken);
        // The password has done its job; keeping it in memory any longer buys nothing.
        setPassword("");
      } else {
        navigate(from, { replace: true });
      }
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: FormEvent) {
    event.preventDefault();
    if (!mfaToken) return;
    setBusy(true);
    setError(null);
    try {
      await completeMfa(mfaToken, code.replace(/\s+/g, ""));
      navigate(from, { replace: true });
    } catch (err) {
      setError(describe(err));
      // An expired ticket cannot be retried with another code; start over.
      if (err instanceof ApiError && err.code === "invalid_token") {
        setMfaToken(null);
        setCode("");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-6 flex items-center gap-2">
          <Activity className="size-5 text-accent" aria-hidden />
          <h1 className="text-lg font-semibold">Sign in to xraypanel</h1>
        </div>

        {mfaToken === null ? (
          <form className="flex flex-col gap-4" onSubmit={submitPassword}>
            <Field label="Username" htmlFor="username">
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </Field>
            <Field label="Password" htmlFor="password">
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Field>
            {error && (
              <p className="text-sm text-bad" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" variant="primary" loading={busy}>
              Continue
            </Button>
          </form>
        ) : (
          <form className="flex flex-col gap-4" onSubmit={submitCode}>
            <p className="text-sm text-muted">Enter the six-digit code from your authenticator app.</p>
            <Field label="Code" htmlFor="code">
              <Input
                id="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9 ]{6,8}"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
                autoFocus
              />
            </Field>
            {error && (
              <p className="text-sm text-bad" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" variant="primary" loading={busy}>
              Sign in
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setMfaToken(null);
                setCode("");
                setError(null);
              }}
            >
              Use a different account
            </Button>
          </form>
        )}
      </Card>
    </div>
  );
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case "invalid_credentials":
        return "Wrong username or password.";
      case "invalid_code":
        return "That code is not valid. Codes change every 30 seconds.";
      case "too_many_attempts":
        return "Too many attempts. Wait a few minutes and try again.";
      case "invalid_token":
        return "The sign-in took too long. Start again.";
    }
    return error.message;
  }
  return "The panel could not be reached.";
}
