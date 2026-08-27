#!/usr/bin/env python3
"""Verify the deployed Olopa MVP from compiler to persisted telemetry read."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


CONTROL_URL = os.getenv("OLOPA_MVP_CONTROL_URL", "http://127.0.0.1:8100").rstrip("/")
INGEST_URL = os.getenv("OLOPA_MVP_INGEST_URL", "http://127.0.0.1:8000").rstrip("/")
CONTROL_TOKEN = os.getenv("OLOPA_MVP_CONTROL_TOKEN", "olopa-local-admin")
INGEST_TOKEN = os.getenv("OLOPA_MVP_INGEST_TOKEN", "olopa-local-ingest")
TENANT_ID = os.getenv("OLOPA_MVP_TENANT", "default")
TIMEOUT_S = float(os.getenv("OLOPA_MVP_SMOKE_TIMEOUT_S", "90"))


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = {"accept": "application/json", **(headers or {})}
    if payload is not None:
        request_headers["content-type"] = "application/json"
    req = urllib.request.Request(
        url,
        data=payload,
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{method} {url} returned invalid JSON: {raw[:200]}") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{method} {url} returned a non-object JSON response")
    return decoded


def wait_for_stack() -> None:
    deadline = time.monotonic() + TIMEOUT_S
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            ingest = request_json("GET", f"{INGEST_URL}/ready")
            control = request_json("GET", f"{CONTROL_URL}/health")
            if ingest.get("ready") is True and control.get("rust_ingest", {}).get("reachable"):
                return
            last_error = f"ingest={ingest!r}, control={control!r}"
        except RuntimeError as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"MVP stack did not become ready within {TIMEOUT_S:g}s: {last_error}")


def compile_rule(control_headers: dict[str, str]) -> None:
    source = '''rule "mvp_exec_seen" {
  from endpoint.process
  correlate process.exec as p
  where p.pid > 0
  respond alert medium
}'''
    result = request_json(
        "POST",
        f"{CONTROL_URL}/api/v1/control/compiler/compile",
        headers=control_headers,
        body={"source": source, "mode": "runtime-ir"},
        timeout=30.0,
    )
    runtime_ir = result.get("runtime_ir")
    if not result.get("ok") or not isinstance(runtime_ir, dict):
        raise RuntimeError(f"OIL compilation failed: {result.get('stderr') or result!r}")
    rules = runtime_ir.get("rules")
    if not isinstance(rules, list) or not any(rule.get("name") == "mvp_exec_seen" for rule in rules):
        raise RuntimeError("compiler response did not contain the MVP rule")


def ingest_and_observe(
    control_headers: dict[str, str], ingest_headers: dict[str, str]
) -> str:
    smoke_id = f"mvp-smoke-{time.time_ns()}"
    batch = {
        "tenant_id": TENANT_ID,
        "host_id": "mvp-smoke-host",
        "schema_version": 2,
        "batch_id": smoke_id,
        "process_exec_events": [
            {
                "pid": os.getpid(),
                "tgid": os.getpid(),
                "ppid": os.getppid(),
                "uid": os.getuid() if hasattr(os, "getuid") else 0,
                "gid": os.getgid() if hasattr(os, "getgid") else 0,
                "comm": "olopa-mvp-smoke",
                "filename": "/usr/bin/olopa-mvp-smoke",
                "attrs": {"mvp_smoke_id": smoke_id},
            }
        ],
    }
    ack = request_json(
        "POST",
        f"{INGEST_URL}/api/v1/ingest/batches",
        headers=ingest_headers,
        body=batch,
    )
    if not ack.get("accepted"):
        raise RuntimeError(f"ingest did not accept the MVP batch: {ack!r}")

    deadline = time.monotonic() + TIMEOUT_S
    query = urllib.parse.urlencode({"limit": 100})
    while time.monotonic() < deadline:
        recent = request_json(
            "GET",
            f"{CONTROL_URL}/api/v1/ingest/recent?{query}",
            headers=control_headers,
        )
        rows = recent.get("rows", [])
        for row in rows if isinstance(rows, list) else []:
            event = row.get("event", {}) if isinstance(row, dict) else {}
            attrs = event.get("attrs", {}) if isinstance(event, dict) else {}
            if isinstance(attrs, dict) and attrs.get("mvp_smoke_id") == smoke_id:
                return smoke_id
        time.sleep(0.25)
    raise RuntimeError("accepted MVP telemetry did not appear through the control plane")


def main() -> int:
    control_headers = {
        "x-dev-token": CONTROL_TOKEN,
        "x-tenant-id": TENANT_ID,
    }
    ingest_headers = {"authorization": f"Bearer {INGEST_TOKEN}"}
    try:
        print("[1/3] waiting for authenticated MVP stack")
        wait_for_stack()
        print("[2/3] compiling OIL rule through the control plane")
        compile_rule(control_headers)
        print("[3/3] ingesting telemetry and reading it through the console API")
        smoke_id = ingest_and_observe(control_headers, ingest_headers)
    except RuntimeError as exc:
        print(f"MVP smoke failed: {exc}", file=sys.stderr)
        return 1
    print(f"MVP smoke passed: {smoke_id}")
    print(f"Console: {CONTROL_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
