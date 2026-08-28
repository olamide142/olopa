# Olopa Console (React 19 SPA)

The control-plane dashboard, rebuilt with React 19 + TypeScript + Vite + Tailwind v4
and shadcn-style components. Served by the FastAPI control plane.

## Develop

```bash
cd app/control_plane/web
npm install
npm run dev          # Vite dev server on :5173, proxies /api + /health to :8100
```

Run the control plane separately so the proxied API is live:

```bash
# from repo root
PYTHONPATH=. app/control_plane/.venv/bin/python -m uvicorn \
  control_server.main:app --app-dir app/control_plane --port 8100
```

Point the dev server at a different backend with `?api=https://console.olopa.io`.

## Build

```bash
npm run build        # type-checks, then emits to ../control_server/webdist
```

The FastAPI control plane serves the build:

- `/ui/*` — hashed JS/CSS assets (`StaticFiles` mount, only when `webdist/` exists)
- `/`, `/fleet`, `/incidents`, `/graph`, `/oil`, `/compiler`, `/rules`, `/deployments`,
  `/install` — return the SPA shell so the in-app router takes over

If `webdist/` is absent, the dashboard route returns a 503 telling you to run the build
— there's no legacy fallback console anymore.

## Layout

```
src/
  lib/        api client + types (mirror ingest_server/src/telemetry.rs), event mapping, utils
  hooks/      useIngestFeed (polling/EPS/series), useTheme
  components/
    ui/       button, card, badge, input/select, status-dot
    layout/   Sidebar, Topbar
    metrics/  Sparkline, StatCard, EventsTable
    panels/   MetricsPanel (live), Placeholder (stubs for un-ported panels)
```

## Status

- **Metrics** — done, wired to `/api/v1/ingest/{stats,summary,recent}`.
- **Fleet / Incidents / Graph / OIL / Compiler / Install** — routed placeholders,
  ported in follow-ups. Fleet depends on a planned `/api/v1/ingest/agents` endpoint
  surfacing per-agent heartbeat health.
