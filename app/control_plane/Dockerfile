# syntax=docker/dockerfile:1.7

FROM caddy:2.8-alpine AS caddy_runtime

# -- React console build -------------------------------------------------------
# Builds the SPA into control_server/webdist (vite base=/ui/, outDir is
# ../control_server/webdist relative to the web/ dir).
FROM node:20-bookworm-slim AS web_build
WORKDIR /build/app/control_plane/web
COPY app/control_plane/web/package.json app/control_plane/web/package-lock.json ./
RUN npm ci --fetch-retries=5 --fetch-retry-mintimeout=20000 --fetch-retry-maxtimeout=120000
COPY app/control_plane/web/ ./
COPY app/design/ /build/app/design/
RUN npm run build
# Built assets now at /build/app/control_plane/control_server/webdist.

FROM rust:1.94-bookworm AS runtime

RUN apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10002 olopa

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VENV_PATH=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONPATH=/opt/olopa

WORKDIR /opt/olopa

COPY app/control_plane/requirements.txt /tmp/requirements.txt
RUN python3 -m venv "${VENV_PATH}" \
    && "${VENV_PATH}/bin/pip" install --no-cache-dir --retries 10 --timeout 120 -r /tmp/requirements.txt

# Control-plane source.
COPY app/control_plane/ ./app/control_plane
COPY app/intel_sync/ ./app/intel_sync
# Built React console (overrides any local webdist; web/ source/node_modules are
# excluded via .dockerignore).
COPY --from=web_build /build/app/control_plane/control_server/webdist ./app/control_plane/control_server/webdist
COPY --from=caddy_runtime /usr/bin/caddy /usr/bin/caddy
COPY app/control_plane/Caddyfile /etc/caddy/Caddyfile
# Static landing + docs site — Caddy serves this directly, FastAPI never sees it.
COPY app/control_plane/site /srv/site

WORKDIR /opt/olopa/app/control_plane

ENV CONTROL_HOST=0.0.0.0
ENV CONTROL_PORT=8100
ENV RUST_INGEST_BASE_URL=http://olopa-ingest:8000
# oilc source is not present in this deployment context by default.
ENV OILC_MANIFEST_PATH=/opt/olopa/app/control_plane/oilc/Cargo.toml

RUN chown -R olopa:olopa /opt/olopa
USER olopa

EXPOSE 8100

CMD ["sh", "-c", "/opt/venv/bin/python -m uvicorn control_server.main:app --host ${CONTROL_HOST:-0.0.0.0} --port ${CONTROL_PORT:-8100}"]
