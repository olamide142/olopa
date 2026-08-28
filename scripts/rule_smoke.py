#!/usr/bin/env python3
"""End-to-end smoke tests for the testable OIL rule collection.

For each rule in `oilc/src/rules/testable/` that the ingest server's central
correlation engine can actually evaluate (process/file/network/db_query —
see docs/oilc/rules-authoring-and-rollout.md for what's excluded and why):

  1. compile the rule's real .oil source through the control plane,
  2. load the compiled runtime IR into the ingest server's correlation
     engine (POST /api/v1/correlate/rules — the step scripts/mvp_smoke.py
     does not perform, so it only proves telemetry round-trips, not that a
     rule fired),
  3. post a positive telemetry fixture and confirm a matching alert appears
     via GET /api/v1/correlate/alerts,
  4. post a negative fixture and confirm no alert appears for it.

Run all cases:
    python scripts/rule_smoke.py

Run one rule:
    python scripts/rule_smoke.py --rule root_ssh_write_by_non_root_process

Requires a running MVP stack (docker-compose.mvp.yml) with correlation
enabled (the default). Loading rules is a global-scope-token action.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "oilc" / "src" / "rules" / "testable"

CONTROL_URL = os.getenv("OLOPA_MVP_CONTROL_URL", "http://127.0.0.1:8100").rstrip("/")
INGEST_URL = os.getenv("OLOPA_MVP_INGEST_URL", "http://127.0.0.1:8000").rstrip("/")
CONTROL_TOKEN = os.getenv("OLOPA_MVP_CONTROL_TOKEN", "olopa-local-admin")
INGEST_TOKEN = os.getenv("OLOPA_MVP_INGEST_TOKEN", "olopa-local-ingest")
TENANT_ID = os.getenv("OLOPA_MVP_TENANT", "default")
TIMEOUT_S = float(os.getenv("OLOPA_MVP_SMOKE_TIMEOUT_S", "30"))


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> Any:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = {"accept": "application/json", **(headers or {})}
    if payload is not None:
        request_headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=payload, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc
    return json.loads(raw) if raw else None


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


@dataclass
class RuleCase:
    name: str  # matches the rule's declared name in .oil source
    source_file: str  # relative to RULES_DIR
    positive_batch: Callable[[str, str], dict[str, Any]]
    negative_batch: Callable[[str, str], dict[str, Any]] | None


def _process(pid: int, uid: int, comm: str, **attrs: str) -> dict[str, Any]:
    return {
        "pid": pid,
        "tgid": pid,
        "ppid": 1,
        "uid": uid,
        "gid": uid,
        "comm": comm,
        "filename": f"/usr/bin/{comm}",
        "attrs": attrs,
    }


def _file(pid: int, uid: int, comm: str, operation: str, path: str) -> dict[str, Any]:
    return {
        "pid": pid,
        "tgid": pid,
        "uid": uid,
        "gid": uid,
        "comm": comm,
        "operation": operation,
        "path": path,
        "attrs": {},
    }


def _net(
    pid: int,
    uid: int,
    comm: str,
    direction: str,
    protocol: str = "tcp",
    dst_port: int | None = None,
    **attrs: str,
) -> dict[str, Any]:
    return {
        "pid": pid,
        "tgid": pid,
        "uid": uid,
        "gid": uid,
        "comm": comm,
        "direction": direction,
        "protocol": protocol,
        "dst_port": dst_port,
        "attrs": attrs,
    }


def _db(
    pid: int,
    uid: int,
    comm: str,
    query_class: int,
    database: str | None = None,
    tables: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "pid": pid,
        "tgid": pid,
        "uid": uid,
        "gid": uid,
        "comm": comm,
        "db_engine": "postgresql",
        "database": database,
        "operation": "other",
        "tables": tables or [],
        "statement_fingerprint": f"fp-{pid}",
        "attrs": {"query_class": str(query_class)},
    }


def _batch(host_id: str, tenant: str, **families: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "tenant_id": tenant,
        "host_id": host_id,
        "schema_version": 2,
        "batch_id": f"{host_id}-{time.time_ns()}",
        **families,
    }


PID = 42000  # bumped per case below so concurrent fixtures never share a pid


def _next_pid() -> int:
    global PID
    PID += 1
    return PID


CASES: list[RuleCase] = [
    RuleCase(
        name="mvp_exec_seen",
        source_file="mvp_exec_seen.oil",
        positive_batch=lambda host, tenant: _batch(
            host, tenant, process_exec_events=[_process(_next_pid(), 1000, "curl")]
        ),
        negative_batch=lambda host, tenant: _batch(host, tenant),
    ),
    RuleCase(
        name="root_ssh_write_by_non_root_process",
        source_file="root_ssh_write_by_non_root_process.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "python")],
            file_events=[_file(pid, 1000, "python", "write", "/root/.ssh/authorized_keys")],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 0, "sshd")],
            file_events=[_file(pid, 0, "sshd", "write", "/root/.ssh/authorized_keys")],
        ))(_next_pid()),
    ),
    RuleCase(
        name="outbound_to_specific_website",
        source_file="outbound_to_specific_website.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "curl")],
            net_events=[_net(pid, 1000, "curl", "outbound", **{"dest.domain": "apple.com"})],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "curl")],
            net_events=[_net(pid, 1000, "curl", "outbound", **{"dest.domain": "example.com"})],
        ))(_next_pid()),
    ),
    RuleCase(
        name="ssl_large_single_encrypt_call",
        source_file="ssl_large_single_encrypt_call.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 0, "suspicious-bin")],
            net_events=[_net(
                pid, 0, "suspicious-bin", "outbound", protocol="tls",
                ssl_operation="encrypt", ssl_data_len="5000000",
            )],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 0, "suspicious-bin")],
            net_events=[_net(
                pid, 0, "suspicious-bin", "outbound", protocol="tls",
                ssl_operation="encrypt", ssl_data_len="1000",
            )],
        ))(_next_pid()),
    ),
    RuleCase(
        name="credential_access_followed_by_egress",
        source_file="credential_access_followed_by_egress.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            file_events=[_file(pid, 1000, "python", "read", "/etc/shadow")],
            net_events=[_net(
                pid, 1000, "python", "outbound",
                **{"bytes_out": "150000", "dest.domain": "evil.example"},
            )],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            file_events=[_file(pid, 1000, "python", "read", "/etc/hosts")],
            net_events=[_net(
                pid, 1000, "python", "outbound",
                **{"bytes_out": "150000", "dest.domain": "evil.example"},
            )],
        ))(_next_pid()),
    ),
    RuleCase(
        name="lateral_movement_after_credential_harvest",
        source_file="lateral_movement_after_credential_harvest.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            file_events=[_file(pid, 0, "ssh", "read", "/etc/shadow")],
            net_events=[_net(pid, 0, "ssh", "outbound", dst_port=22)],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            file_events=[_file(pid, 0, "ssh", "read", "/etc/shadow")],
            net_events=[_net(pid, 0, "ssh", "outbound", dst_port=8080)],
        ))(_next_pid()),
    ),
    RuleCase(
        name="block_untrusted_finance_reads",
        source_file="block_untrusted_finance_reads.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "untrusted-worker")],
            db_query_events=[_db(pid, 1000, "untrusted-worker", 1, "finance", ["ledger"])],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "trusted-worker")],
            db_query_events=[_db(pid, 1000, "trusted-worker", 1, "finance", ["ledger"])],
        ))(_next_pid()),
    ),
    RuleCase(
        name="sql_privilege_grant_from_unprivileged_proc",
        source_file="sql_privilege_grant_from_unprivileged_proc.oil",
        positive_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "app-service")],
            db_query_events=[_db(pid, 1000, "app-service", 4)],
        ))(_next_pid()),
        negative_batch=lambda host, tenant: (lambda pid: _batch(
            host, tenant,
            process_exec_events=[_process(pid, 1000, "app-service")],
            db_query_events=[_db(pid, 1000, "app-service", 1)],
        ))(_next_pid()),
    ),
]


def find_alert(
    ingest_headers: dict[str, str], tenant: str, rule_name: str, host_id: str
) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({"tenant_id": tenant, "limit": 200})
    alerts = request_json("GET", f"{INGEST_URL}/api/v1/correlate/alerts?{query}", headers=ingest_headers)
    for alert in alerts or []:
        if alert.get("rule_name") == rule_name and alert.get("host_id") == host_id:
            return alert
    return None


def wait_for_alert(
    ingest_headers: dict[str, str], tenant: str, rule_name: str, host_id: str
) -> dict[str, Any] | None:
    deadline = time.monotonic() + TIMEOUT_S
    while time.monotonic() < deadline:
        alert = find_alert(ingest_headers, tenant, rule_name, host_id)
        if alert is not None:
            return alert
        time.sleep(0.25)
    return None


def run_case(case: RuleCase, control_headers: dict[str, str], ingest_headers: dict[str, str]) -> None:
    source = (RULES_DIR / case.source_file).read_text()

    compiled = request_json(
        "POST",
        f"{CONTROL_URL}/api/v1/control/compiler/compile",
        headers=control_headers,
        body={"source": source, "mode": "runtime-ir"},
        timeout=30.0,
    )
    if not compiled.get("ok") or not isinstance(compiled.get("runtime_ir"), dict):
        raise RuntimeError(f"{case.name}: compile failed: {compiled.get('stderr') or compiled!r}")

    loaded = request_json(
        "POST",
        f"{INGEST_URL}/api/v1/correlate/rules",
        headers=ingest_headers,
        body=compiled["runtime_ir"],
        timeout=15.0,
    )
    if not loaded or not loaded.get("loaded"):
        raise RuntimeError(f"{case.name}: no rules loaded into correlation engine: {loaded!r}")

    pos_host = f"rule-smoke-{case.name}-pos-{time.time_ns()}"
    pos_batch = case.positive_batch(pos_host, TENANT_ID)
    ack = request_json("POST", f"{INGEST_URL}/api/v1/ingest/batches", headers=ingest_headers, body=pos_batch)
    if not ack.get("accepted"):
        raise RuntimeError(f"{case.name}: positive fixture batch not accepted: {ack!r}")

    alert = wait_for_alert(ingest_headers, TENANT_ID, case.name, pos_host)
    if alert is None:
        raise RuntimeError(f"{case.name}: [FAIL] expected an alert for the positive fixture, none appeared")
    print(f"  [pos] {case.name}: matched, severity={alert.get('severity')}")

    if case.negative_batch is not None:
        neg_host = f"rule-smoke-{case.name}-neg-{time.time_ns()}"
        neg_batch = case.negative_batch(neg_host, TENANT_ID)
        ack = request_json("POST", f"{INGEST_URL}/api/v1/ingest/batches", headers=ingest_headers, body=neg_batch)
        if not ack.get("accepted"):
            raise RuntimeError(f"{case.name}: negative fixture batch not accepted: {ack!r}")
        time.sleep(1.0)
        stray = find_alert(ingest_headers, TENANT_ID, case.name, neg_host)
        if stray is not None:
            raise RuntimeError(f"{case.name}: [FAIL] negative fixture unexpectedly matched")
        print(f"  [neg] {case.name}: correctly did not match")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rule", help="run only the named rule case")
    args = parser.parse_args()

    cases = CASES
    if args.rule:
        cases = [c for c in CASES if c.name == args.rule]
        if not cases:
            names = ", ".join(c.name for c in CASES)
            print(f"unknown rule {args.rule!r}; available: {names}", file=sys.stderr)
            return 2

    control_headers = {"x-dev-token": CONTROL_TOKEN, "x-tenant-id": TENANT_ID}
    ingest_headers = {"authorization": f"Bearer {INGEST_TOKEN}"}

    print("[1/2] waiting for MVP stack")
    wait_for_stack()

    print(f"[2/2] running {len(cases)} rule case(s)")
    failures: list[str] = []
    for case in cases:
        try:
            run_case(case, control_headers, ingest_headers)
        except RuntimeError as exc:
            print(f"  {exc}", file=sys.stderr)
            failures.append(case.name)

    if failures:
        print(f"\nrule smoke FAILED: {', '.join(failures)}", file=sys.stderr)
        return 1

    print(f"\nrule smoke passed: {len(cases)} rule(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
