# syntax=docker/dockerfile:1.7

FROM rust:1.94-bookworm AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10002 olopa

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/olopa

COPY app/control_plane/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Control-plane source plus oilc (used by compile endpoint).
COPY app/control_plane ./app/control_plane
COPY oilc ./oilc

WORKDIR /opt/olopa/app/control_plane

ENV CONTROL_HOST=0.0.0.0
ENV CONTROL_PORT=8100
ENV RUST_INGEST_BASE_URL=http://ingest-server:8000
ENV OILC_MANIFEST_PATH=/opt/olopa/oilc/Cargo.toml

RUN chown -R olopa:olopa /opt/olopa
USER olopa

EXPOSE 8100

CMD ["sh", "-c", "python3 -m uvicorn control_server.main:app --host ${CONTROL_HOST:-0.0.0.0} --port ${CONTROL_PORT:-8100}"]
