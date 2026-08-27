# syntax=docker/dockerfile:1.7

FROM rust:1.94-bookworm AS builder

ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_TIMEOUT=600
ENV CARGO_HTTP_LOW_SPEED_LIMIT=1

WORKDIR /build

# Prime dependency cache.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --locked --release \
    && rm -rf src

# Build real binary.
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

RUN apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 olopa

WORKDIR /app

COPY --from=builder /build/target/release/olopa-ingest /usr/local/bin/olopa-ingest

RUN mkdir -p /var/lib/olopa/ingest \
    && chown -R olopa:olopa /var/lib/olopa

USER olopa

EXPOSE 8000

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8000
ENV INGEST_PERSIST_JSONL_PATH=/var/lib/olopa/ingest/events.jsonl
ENV INGEST_WAL_PATH=/var/lib/olopa/ingest/acceptance.wal
ENV INGEST_DEDUPE_PATH=/var/lib/olopa/ingest/dedupe.json
ENV INGEST_DEAD_LETTER_PATH=/var/lib/olopa/ingest/dead-letter.jsonl

CMD ["sh", "-lc", "HOST_BIND=\"${SERVER_HOST:-0.0.0.0}\"; PORT_BIND=\"${PORT:-${SERVER_PORT:-8000}}\"; echo \"[ingest] boot host=${HOST_BIND} port=${PORT_BIND}\"; exec /usr/local/bin/olopa-ingest --host \"${HOST_BIND}\" --port \"${PORT_BIND}\""]
