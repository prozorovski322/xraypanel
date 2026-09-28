# The web image: Caddy with the built admin UI and subscription page.
#
# Caddy is the only thing on 80 and 443. It gets and renews the certificate, serves the
# static files, and proxies /api and /sub to the panel. The panel's node port does not go
# through it: nodes authenticate with client certificates, and terminating that TLS here
# would erase the identity the panel checks.
#
# Build:
#   docker build -f deploy/web.Dockerfile -t xraypanel-web .

# ------------------------------------------------------------------ build the UI

# The output is static files, identical for every architecture, so it is built once on the
# build machine's own platform.
FROM --platform=$BUILDPLATFORM node:24-alpine AS ui

WORKDIR /ui

# Dependencies first, so a source change does not reinstall them. npm ci refuses a lockfile
# that disagrees with package.json and checks every package against its recorded hash.
COPY frontend/package.json frontend/package-lock.json ./
RUN PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --no-audit --no-fund

COPY frontend/ ./
# Type-check and build. The API types are committed, so the contract is not needed here.
RUN npm run build

# ------------------------------------------------------------------ image

FROM caddy:2.10-alpine

COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=ui /ui/dist /srv

# Source maps are for debugging a build, not for publishing: they would hand every visitor
# the full source of the admin UI, comments included. The Caddyfile is validated here, so a
# broken one fails the image build rather than the first start on a server. The domain is a
# placeholder for the check only; validation obtains no certificate.
RUN find /srv -name '*.map' -delete \
 && PANEL_DOMAIN=panel.example.com caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
