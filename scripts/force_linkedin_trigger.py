#!/usr/bin/env python3
"""
Force-trigger helper for `oilc/src/rules/linkedin_showcase.oil`.

Assumptions:
- olopa agent is already running,
- runtime IR containing linkedin showcase rules is already loaded,
- ingest server is already running.

This script focuses on the deterministic graph rule path:
  linkedin_demo_graph_lateral_shape
which fires when outbound connects to lateral ports burst within 5m.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def env_float(key: str, default: float) -> float:
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_int(key: str, default: int) -> int:
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def fetch_recent_rows(
    base_url: str,
    limit: int,
    tenant_id: str | None,
    api_token: str | None,
    api_key: str | None,
    timeout_sec: float,
) -> dict[str, Any]:
    query: dict[str, Any] = {"limit": limit}
    if tenant_id:
        query["tenant_id"] = tenant_id
    url = f"{base_url.rstrip('/')}/api/v1/ingest/recent?{urllib.parse.urlencode(query)}"

    headers: dict[str, str] = {}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    elif api_key:
        headers["x-api-key"] = api_key

    req = urllib.request.Request(url=url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def extract_rule_hits(payload: dict[str, Any], expected_rule: str) -> list[dict[str, Any]]:
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return []

    hits: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        event = row.get("event")
        if not isinstance(event, dict):
            continue
        attrs = event.get("attrs")
        if not isinstance(attrs, dict):
            continue
        if attrs.get("rule_name") == expected_rule:
            hits.append(row)
    return hits


def try_print_agent_status() -> None:
    try:
        proc = subprocess.run(
            ["olopa", "status", "--verbose", "--no-mascot"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return

    print("\nCurrent agent status:")
    print(proc.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="force_linkedin_trigger.py",
        description="Force trigger linkedin showcase rule against running olopa components.",
    )
    parser.add_argument("--target-ip", default=os.getenv("TARGET_IP", "127.0.0.1"))
    parser.add_argument("--target-port", type=int, default=env_int("TARGET_PORT", 22))
    parser.add_argument("--burst-count", type=int, default=env_int("BURST_COUNT", 12))
    parser.add_argument(
        "--burst-sleep-sec", type=float, default=env_float("BURST_SLEEP_SEC", 0.08)
    )
    parser.add_argument(
        "--post-burst-wait-sec",
        type=float,
        default=env_float("POST_BURST_WAIT_SEC", 1.5),
    )
    parser.add_argument(
        "--connect-timeout-sec",
        type=float,
        default=env_float("CONNECT_TIMEOUT_SEC", 0.35),
    )
    parser.add_argument(
        "--ingest-base-url",
        default=os.getenv("INGEST_BASE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID"))
    parser.add_argument(
        "--expected-rule",
        default=os.getenv("EXPECTED_RULE", "linkedin_demo_graph_lateral_shape"),
    )
    parser.add_argument(
        "--poll-timeout-sec",
        type=float,
        default=env_float("POLL_TIMEOUT_SEC", 15.0),
    )
    parser.add_argument(
        "--poll-interval-sec",
        type=float,
        default=env_float("POLL_INTERVAL_SEC", 0.75),
    )
    parser.add_argument(
        "--ingest-api-token",
        default=os.getenv("INGEST_API_TOKEN") or os.getenv("OLOPA_INGEST_API_TOKEN"),
    )
    parser.add_argument("--ingest-api-key", default=os.getenv("INGEST_API_KEY"))
    parser.add_argument(
        "--recent-limit",
        type=int,
        default=env_int("RECENT_LIMIT", 500),
        help="How many recent rows to scan from ingest API.",
    )
    args = parser.parse_args()

    print("[1/3] Generating outbound connect burst...")
    print(
        f"Target: {args.target_ip}:{args.target_port} | "
        f"count={args.burst_count} | sleep={args.burst_sleep_sec:.3f}s"
    )

    for _ in range(max(args.burst_count, 0)):
        try:
            with socket.create_connection(
                (args.target_ip, args.target_port),
                timeout=max(args.connect_timeout_sec, 0.01),
            ):
                pass
        except OSError:
            # Failure is acceptable; attempted connect still emits events on most paths.
            pass
        time.sleep(max(args.burst_sleep_sec, 0.0))

    time.sleep(max(args.post_burst_wait_sec, 0.0))

    print("[2/3] Polling ingest API for rule hits...")
    deadline = time.time() + max(args.poll_timeout_sec, 0.1)
    last_error: str | None = None
    hits: list[dict[str, Any]] = []

    while time.time() < deadline:
        try:
            payload = fetch_recent_rows(
                base_url=args.ingest_base_url,
                limit=max(args.recent_limit, 1),
                tenant_id=args.tenant_id,
                api_token=args.ingest_api_token,
                api_key=args.ingest_api_key,
                timeout_sec=3.0,
            )
            hits = extract_rule_hits(payload, args.expected_rule)
            if hits:
                break
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code} while querying ingest recent endpoint"
        except Exception as exc:  # noqa: BLE001 - best-effort polling in demo helper.
            last_error = str(exc)
        time.sleep(max(args.poll_interval_sec, 0.1))

    print("[3/3] Result")
    if hits:
        print(
            f"SUCCESS: detected {len(hits)} ingest row(s) with "
            f"rule_name={args.expected_rule!r}."
        )
        print("\nRecent matching rows (up to 5):")
        for row in hits[:5]:
            event = row.get("event", {})
            attrs = event.get("attrs", {}) if isinstance(event, dict) else {}
            print(
                "- "
                f"tenant={row.get('tenant_id')} "
                f"host={row.get('host_id')} "
                f"kind={row.get('event_kind')} "
                f"ingested_at={row.get('ingested_at_unix_ms')} "
                f"rule_id={attrs.get('rule_id')} "
                f"rule_name={attrs.get('rule_name')}"
            )
        return 0

    print("No matching rule hits found before timeout.")
    if last_error:
        print(f"Last ingest API error: {last_error}")
    print("Possible causes:")
    print("- linkedin runtime IR is not loaded in the running agent")
    print("- net probes are not attached on this host/kernel")
    print("- ingest auth/tenant filters blocked visibility")
    print("- destination connect path is not producing captured net events")
    try_print_agent_status()
    return 1


if __name__ == "__main__":
    sys.exit(main())

