import createClient from "openapi-fetch";

import type { components, paths } from "./schema";

export type Schemas = components["schemas"];

/**
 * The access token lives in memory and nowhere else.
 *
 * Not localStorage: anything that can run script on the page can read it, and a token there
 * outlives the tab. The refresh token is an httpOnly cookie the page cannot read at all, so a
 * reload costs one refresh call and an XSS costs the attacker the rest of fifteen minutes
 * rather than the account.
 */
let accessToken: string | null = null;

/** Listeners told when the session ends, so the app can return to the login screen. */
const sessionEndedListeners = new Set<() => void>();

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function onSessionEnded(listener: () => void): () => void {
  sessionEndedListeners.add(listener);
  return () => sessionEndedListeners.delete(listener);
}

function endSession(): void {
  accessToken = null;
  for (const listener of sessionEndedListeners) listener();
}

export type LoginResponse = Schemas["LoginResponse"];

/**
 * refreshSession exchanges the refresh cookie for a new access token.
 *
 * Single-flight: a page that fires six requests at once and gets six 401s must refresh once.
 * Six concurrent refreshes would present the same refresh token six times, and the panel
 * treats a rotated token presented again as theft and revokes the whole session (the
 * replay detection from M2) — the SPA would log itself out.
 */
let refreshing: Promise<boolean> | null = null;

export function refreshSession(): Promise<boolean> {
  if (refreshing) return refreshing;

  refreshing = (async () => {
    try {
      const response = await fetch("/api/v1/auth/refresh", {
        method: "POST",
        credentials: "same-origin",
      });
      if (!response.ok) return false;
      const body = (await response.json()) as LoginResponse;
      if (!body.access_token) return false;
      accessToken = body.access_token;
      return true;
    } catch {
      return false;
    } finally {
      // Released after the await, so callers that arrived during the refresh share it and
      // the next genuine expiry fifteen minutes later starts a new one.
      queueMicrotask(() => {
        refreshing = null;
      });
    }
  })();

  return refreshing;
}

/**
 * authFetch adds the access token and survives its expiry.
 *
 * On a 401 it refreshes once and replays the request. The request is cloned before the first
 * attempt because a body can only be read once, and a replayed POST with an empty body
 * would be a different request from the one the user made.
 */
/**
 * Endpoints that do not take an access token. A 401 from them is an answer about credentials
 * — a wrong password, a bad code, a spent refresh cookie — and refreshing and replaying would
 * only repeat it. Everything else under /auth (me, password, TOTP, logout-all) does take the
 * token and must be retried like any other call: enabling 2FA or changing the password moves
 * the panel's "tokens valid from" mark, and the request right after it is exactly the one that
 * needs a fresh token.
 */
const credentialEndpoints = ["/auth/login", "/auth/login/mfa", "/auth/refresh", "/auth/logout"];

function isCredentialEndpoint(url: string): boolean {
  const path = new URL(url, window.location.origin).pathname.replace(/^\/api\/v1/, "");
  return credentialEndpoints.includes(path);
}

async function authFetch(request: Request): Promise<Response> {
  const retry = request.clone();

  if (accessToken) request.headers.set("Authorization", `Bearer ${accessToken}`);
  const response = await fetch(request);

  if (response.status !== 401 || isCredentialEndpoint(request.url)) {
    return response;
  }

  const refreshed = await refreshSession();
  if (!refreshed) {
    endSession();
    return response;
  }

  retry.headers.set("Authorization", `Bearer ${accessToken}`);
  const replayed = await fetch(retry);
  if (replayed.status === 401) endSession();
  return replayed;
}

export const api = createClient<paths>({
  baseUrl: "/api/v1",
  fetch: authFetch,
  credentials: "same-origin",
});

/** ApiError carries the panel's error envelope so screens can show its message. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly requestId: string | undefined;

  constructor(status: number, body: unknown) {
    const envelope = (body ?? {}) as Partial<Schemas["Error"]>;
    super(envelope.message || envelope.code || `request failed with status ${status}`);
    this.status = status;
    this.code = envelope.code;
    this.requestId = envelope.request_id;
  }
}

/**
 * unwrap turns an openapi-fetch result into data or a thrown ApiError, which is the shape
 * TanStack Query expects from a query function.
 */
export function unwrap<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.error !== undefined || !result.response.ok) {
    throw new ApiError(result.response.status, result.error);
  }
  return result.data as T;
}

/**
 * idempotencyKey makes a create safe to retry. A double-clicked "create user" or a request
 * resent after a timeout then returns the first result instead of making a second user.
 */
export function idempotencyKey(): string {
  return crypto.randomUUID();
}
