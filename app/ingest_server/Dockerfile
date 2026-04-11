# syntax=docker/dockerfile:1.7

FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Prime dependency cache.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Build real binary.
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
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

CMD ["sh", "-lc", ": \"${SERVER_HOST:=0.0.0.0}\"; : \"${SERVER_PORT:=${PORT:-8000}}\"; exec /usr/local/bin/olopa-ingest"]
