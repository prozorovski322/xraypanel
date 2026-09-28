import { fileURLToPath, URL } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type ProxyOptions } from "vite";

// The panel's HTTP port. The dev server proxies the API to it so the browser sees one
// origin, which is what the refresh cookie (SameSite=Strict, scoped to /api/v1/auth) needs.
const panel = process.env.PANEL_URL ?? "http://127.0.0.1:8080";

/**
 * The same split the production Caddyfile makes for /sub/{token}: a browser asking for a page
 * gets the subscription page, and everything else — a client, curl, the page's own fetch of
 * /info — goes to the panel. Kept identical to deploy/Caddyfile so that what works here works
 * there.
 */
const subscription: ProxyOptions = {
  target: panel,
  bypass(req) {
    const url = new URL(req.url ?? "/", "http://dev");
    const wantsPage =
      /^\/sub\/[^/]+\/?$/.test(url.pathname) &&
      (req.headers.accept ?? "").includes("text/html") &&
      !url.searchParams.has("format");
    return wantsPage ? "/sub.html" : undefined;
  },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    // IPv4 loopback explicitly. "localhost" resolves to ::1 first on current Node, and a dev
    // server listening only there is unreachable from anything that dials 127.0.0.1 — which
    // on this machine includes the sandboxed tools and the embedded browser.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      // changeOrigin stays off on purpose. The panel refuses a token refresh whose Origin
      // host differs from the request's Host, and rewriting Host to the panel's address
      // would make every refresh from the dev server look cross-site.
      "/api": { target: panel },
      "/sub": subscription,
      "/healthz": { target: panel },
      "/readyz": { target: panel },
    },
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy: {
      "/api": { target: panel },
      "/sub": subscription,
    },
  },
  build: {
    sourcemap: true,
    rollupOptions: {
      // Two pages: the admin UI, and the public subscription page Caddy serves for /sub/*.
      input: {
        admin: fileURLToPath(new URL("./index.html", import.meta.url)),
        sub: fileURLToPath(new URL("./sub.html", import.meta.url)),
      },
      // Framework chunks apart from the app: the app changes with every release and the
      // framework does not, so browsers keep the larger half cached across deploys. React is
      // split from the admin-only libraries so that the subscription page, opened on a phone
      // by someone who never sees the admin UI, does not download a router and a query cache.
      output: {
        manualChunks(id: string) {
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return "react";
          if (/[\\/]node_modules[\\/](react-router|@tanstack)[\\/]/.test(id)) return "vendor";
          return undefined;
        },
      },
    },
  },
});
