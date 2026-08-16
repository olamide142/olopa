#!/usr/bin/env python3
"""Secure Connect orchestration load test.

Drives N virtual endpoints through the real agent contract — enroll, start a
session, heartbeat on a cadence, then get revoked — against a running control
plane, and reports latency percentiles against the SLO targets in
`docs/secure-connect/implementation-plan.md`.

It exits non-zero when a target is missed, so it can gate a release or a
game-day exercise rather than just printing numbers.

    python tools/sc_loadtest.py --control-url http://127.0.0.1:8100 \
        --dev-token "$CONTROL_DEV_TOKEN" --devices 200 --duration 60

This talks to the orchestrator only. It does not bring up WireGuard interfaces,
so it measures control-plane capacity, not data-plane throughput.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import secrets
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

import httpx

BASE = "/api/v1/secure-connect"

# Targets from the implementation plan, in milliseconds.
SLO_TARGETS = {
    "session_start": ("session establish p95", 8_000),
    "policy_push": ("policy push apply p95", 5_000),
    "revoke_propagation": ("revoke propagation p95", 10_000),
}
REVOKE_ENGINEERING_TARGET_MS = 3_000


def wg_key() -> str:
    """A syntactically valid Curve25519 public key. No tunnel is established."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


@dataclass
class Samples:
    """Latency samples for one operation."""

    name: str
    values: List[float] = field(default_factory=list)
    errors: int = 0

    def add(self, started: float) -> None:
        self.values.append((time.perf_counter() - started) * 1000)

    def percentile(self, pct: float) -> float:
        if not self.values:
            return 0.0
        ordered = sorted(self.values)
        index = min(len(ordered) - 1, int(len(ordered) * pct))
        return ordered[index]

    def summary(self) -> Dict[str, float]:
        if not self.values:
            return {"count": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0}
        return {
            "count": len(self.values),
            "p50": self.percentile(0.50),
            "p95": self.percentile(0.95),
            "p99": self.percentile(0.99),
            "max": max(self.values),
            "mean": statistics.fmean(self.values),
        }


@dataclass
class VirtualDevice:
    index: int
    host_id: str
    device_id: str = ""
    session_id: str = ""
    profile_version: int = 1
    last_nonce: int = 0
    quarantined_at: Optional[float] = None
    revoke_ms: Optional[float] = None


class LoadTest:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.admin_headers = self._auth_headers()
        # Virtual endpoints present the same fingerprint header a real agent
        # would receive from the TLS terminator.
        self.agent_headers = {
            **self.admin_headers,
            "x-olopa-client-cert-fingerprint": f"sha256:loadtest-{uuid.uuid4().hex[:16]}",
        }
        self.tenant = args.tenant
        self.metrics: Dict[str, Samples] = {
            name: Samples(name)
            for name in ("enroll", "session_start", "heartbeat", "policy_push", "revoke_propagation")
        }
        self.devices: List[VirtualDevice] = []
        self.transport_errors: Dict[str, int] = {}
        self.profile_id = ""
        self.gateway_id = args.gateway_id or ""

    def _auth_headers(self) -> Dict[str, str]:
        if self.args.dev_token:
            return {"x-dev-token": self.args.dev_token}
        if self.args.bearer:
            return {"authorization": f"Bearer {self.args.bearer}"}
        raise SystemExit("provide --dev-token or --bearer")

    # -- setup ----------------------------------------------------------------

    async def provision(self, client: httpx.AsyncClient) -> None:
        """Create the gateway and profile the run needs, unless reusing them."""
        run = uuid.uuid4().hex[:8]

        if not self.gateway_id:
            resp = await client.post(
                f"{BASE}/gateways",
                json={
                    "name": f"loadtest-{run}",
                    "region": "loadtest",
                    "public_key": wg_key(),
                    "public_endpoint": "198.51.100.200:51820",
                    # /16 so address allocation is never the bottleneck.
                    "client_cidr": "10.200.0.0/16",
                    "capacity": max(self.args.devices * 2, 1000),
                    "dedicated": True,
                },
                headers=self.admin_headers,
            )
            resp.raise_for_status()
            self.gateway_id = resp.json()["id"]

        resp = await client.post(
            f"{BASE}/profiles",
            json={
                "name": f"loadtest-{run}",
                "access_mode": "split_tunnel",
                "region": "loadtest",
                "allowed_cidrs": ["10.0.0.0/8"],
                "safe_cidrs": ["10.0.9.0/24"],
                "session_ttl_secs": 3600,
                "rekey_interval_secs": 3600,
            },
            headers=self.admin_headers,
        )
        resp.raise_for_status()
        self.profile_id = resp.json()["id"]

        self.devices = [
            VirtualDevice(index=i, host_id=f"loadtest-{run}-host-{i}")
            for i in range(self.args.devices)
        ]

    # -- phases ---------------------------------------------------------------

    async def enroll(self, client: httpx.AsyncClient, device: VirtualDevice) -> None:
        token_resp = await client.post(
            f"{BASE}/enrollment-tokens",
            json={
                "user_id": f"loadtest-{device.index}@example.com",
                "device_hint": device.host_id,
                "profile_id": self.profile_id,
                "ttl_minutes": 15,
            },
            headers=self.admin_headers,
        )
        token_resp.raise_for_status()

        started = time.perf_counter()
        resp = await client.post(
            f"{BASE}/enroll",
            json={
                "enrollment_token": token_resp.json()["token"],
                "tenant_id": self.tenant,
                "host_id": device.host_id,
                "user_id": f"loadtest-{device.index}@example.com",
                "device_fingerprint": f"loadtest-{device.host_id}",
                "wireguard_public_key": wg_key(),
                "posture": {"agent_version": "loadtest", "kernel_verified_posture": False},
            },
            headers=self.agent_headers,
        )
        if resp.status_code != 200:
            self.metrics["enroll"].errors += 1
            return
        self.metrics["enroll"].add(started)
        device.device_id = resp.json()["device_id"]

    async def start_session(self, client: httpx.AsyncClient, device: VirtualDevice) -> None:
        if not device.device_id:
            return
        started = time.perf_counter()
        resp = await client.post(
            f"{BASE}/sessions/start",
            json={
                "tenant_id": self.tenant,
                "device_id": device.device_id,
                "host_id": device.host_id,
                "wireguard_public_key": wg_key(),
                "posture": {"agent_version": "loadtest"},
            },
            headers=self.agent_headers,
        )
        if resp.status_code != 200:
            self.metrics["session_start"].errors += 1
            return
        self.metrics["session_start"].add(started)
        body = resp.json()
        device.session_id = body["session_id"]
        device.profile_version = body["profile"]["profile_version"]
        device.last_nonce = body["command_nonce"]

    async def heartbeat(self, client: httpx.AsyncClient, device: VirtualDevice) -> None:
        if not device.session_id:
            return
        started = time.perf_counter()
        resp = await client.post(
            f"{BASE}/sessions/{device.session_id}/heartbeat",
            json={
                "tenant_id": self.tenant,
                "device_id": device.device_id,
                "session_id": device.session_id,
                "state": "healthy",
                "posture": {"agent_version": "loadtest"},
                "profile_version": device.profile_version,
                "last_command_nonce": device.last_nonce,
                "last_handshake_unix": int(time.time()),
                "bytes_tx": 1024,
                "bytes_rx": 2048,
            },
            headers=self.agent_headers,
        )
        if resp.status_code != 200:
            self.metrics["heartbeat"].errors += 1
            return
        self.metrics["heartbeat"].add(started)

        body = resp.json()
        if body.get("command_nonce"):
            device.last_nonce = body["command_nonce"]
        if body.get("profile"):
            device.profile_version = body["profile"]["profile_version"]
            self.metrics["policy_push"].add(started)
        # Time from queuing the revocation to the endpoint being told about it.
        if body.get("action") == "quarantine" and device.quarantined_at is not None:
            device.revoke_ms = (time.perf_counter() - device.quarantined_at) * 1000
            self.metrics["revoke_propagation"].values.append(device.revoke_ms)
            device.session_id = ""

    # -- driver ---------------------------------------------------------------

    async def run_phase(self, client, coro_factory, items, label: str) -> None:
        semaphore = asyncio.Semaphore(self.args.concurrency)
        phase = label.split()[0]

        async def guarded(item):
            async with semaphore:
                try:
                    await coro_factory(client, item)
                except httpx.HTTPError as exc:
                    # Never swallow a transport failure: a load test that hides
                    # timeouts reports healthy percentiles for a broken system.
                    self.transport_errors[f"{phase}:{type(exc).__name__}"] = (
                        self.transport_errors.get(f"{phase}:{type(exc).__name__}", 0) + 1
                    )

        started = time.perf_counter()
        await asyncio.gather(*(guarded(item) for item in items))
        elapsed = time.perf_counter() - started
        print(f"  {label}: {len(items)} in {elapsed:.1f}s "
              f"({len(items) / max(elapsed, 1e-6):.0f}/s)")

    async def heartbeat_loop(self, client: httpx.AsyncClient) -> None:
        deadline = time.perf_counter() + self.args.duration
        rounds = 0
        while time.perf_counter() < deadline:
            active = [d for d in self.devices if d.session_id]
            if not active:
                break
            await self.run_phase(
                client, self.heartbeat, active, f"heartbeat round {rounds + 1}"
            )
            rounds += 1
            await asyncio.sleep(self.args.heartbeat_interval)

    async def revoke_sample(self, client: httpx.AsyncClient) -> None:
        """Quarantine a slice of the fleet and measure propagation."""
        active = [d for d in self.devices if d.session_id]
        sample = active[: max(1, int(len(active) * self.args.revoke_fraction))]
        if not sample:
            return

        print(f"\n  revoking {len(sample)} session(s)")
        for device in sample:
            device.quarantined_at = time.perf_counter()
            try:
                await client.post(
                    f"{BASE}/devices/{device.device_id}/quarantine",
                    json={"reason": "loadtest revocation"},
                    headers=self.admin_headers,
                )
            except httpx.HTTPError:
                device.quarantined_at = None

        # One heartbeat round is what a real endpoint would do next.
        await self.run_phase(client, self.heartbeat, sample, "revocation heartbeat")

    async def execute(self) -> int:
        limits = httpx.Limits(
            max_connections=self.args.concurrency * 2,
            max_keepalive_connections=self.args.concurrency,
        )
        async with httpx.AsyncClient(
            base_url=self.args.control_url.rstrip("/"),
            timeout=self.args.timeout,
            limits=limits,
        ) as client:
            print(f"provisioning against {self.args.control_url}")
            await self.provision(client)
            print(f"  gateway={self.gateway_id} profile={self.profile_id} "
                  f"devices={self.args.devices} concurrency={self.args.concurrency}\n")

            await self.run_phase(client, self.enroll, self.devices, "enroll")
            await self.run_phase(client, self.start_session, self.devices, "session start")
            await self.heartbeat_loop(client)
            await self.revoke_sample(client)

        return self.report()

    # -- reporting ------------------------------------------------------------

    def report(self) -> int:
        print("\n" + "=" * 72)
        print(f"{'operation':<22}{'count':>8}{'p50':>10}{'p95':>10}{'p99':>10}{'max':>10}")
        print("-" * 72)
        for name, samples in self.metrics.items():
            s = samples.summary()
            if not s["count"]:
                continue
            print(
                f"{name:<22}{int(s['count']):>8}{s['p50']:>9.0f}ms"
                f"{s['p95']:>9.0f}ms{s['p99']:>9.0f}ms{s['max']:>9.0f}ms"
            )

        errors = {n: s.errors for n, s in self.metrics.items() if s.errors}
        if errors:
            print(f"\nrejected responses: {errors}")
        if self.transport_errors:
            print(f"transport failures: {self.transport_errors}")

        print("\nSLO check")
        failures = 0
        for key, (label, target_ms) in SLO_TARGETS.items():
            samples = self.metrics[key]
            if not samples.values:
                print(f"  - {label:<32} no samples")
                continue
            observed = samples.percentile(0.95)
            ok = observed <= target_ms
            failures += 0 if ok else 1
            print(
                f"  {'PASS' if ok else 'FAIL'} {label:<32} "
                f"{observed:>7.0f}ms  target <= {target_ms}ms"
            )

        revoke = self.metrics["revoke_propagation"]
        if revoke.values:
            observed = revoke.percentile(0.95)
            met = observed <= REVOKE_ENGINEERING_TARGET_MS
            print(
                f"  {'PASS' if met else 'MISS'} {'revoke engineering target':<32} "
                f"{observed:>7.0f}ms  target <= {REVOKE_ENGINEERING_TARGET_MS}ms"
                f"{'' if met else '  (advisory, not a failure)'}"
            )

        if errors or self.transport_errors:
            failures += 1
        print("=" * 72)
        return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure Connect orchestration load test")
    parser.add_argument("--control-url", default=os.getenv("CONTROL_URL", "http://127.0.0.1:8100"))
    parser.add_argument("--dev-token", default=os.getenv("CONTROL_DEV_TOKEN", ""))
    parser.add_argument("--bearer", default=os.getenv("CONTROL_BEARER", ""))
    parser.add_argument("--tenant", default=os.getenv("CONTROL_TENANT", "default"))
    parser.add_argument("--devices", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=25)
    parser.add_argument("--duration", type=float, default=30.0, help="heartbeat phase seconds")
    parser.add_argument("--heartbeat-interval", type=float, default=5.0)
    parser.add_argument("--revoke-fraction", type=float, default=0.1)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--gateway-id", default="", help="reuse an existing gateway")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.devices < 1:
        raise SystemExit("--devices must be at least 1")
    return asyncio.run(LoadTest(args).execute())


if __name__ == "__main__":
    sys.exit(main())
