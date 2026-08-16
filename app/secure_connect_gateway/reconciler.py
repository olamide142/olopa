"""Olopa Secure Connect gateway reconciler.

The control plane is the authority for which endpoints may reach a gateway; it
never pushes configuration outward. This agent runs beside `wg` on a gateway
host, pulls the desired peer set from
`GET /api/v1/secure-connect/gateways/{id}/peers`, and reconciles the local
WireGuard interface toward it.

Design rules:

- **Additive-safe, subtractive-deliberate.** Peers the control plane no longer
  lists are removed, because that removal *is* the revocation path. Nothing
  else about the interface (private key, listen port, addresses) is touched.
- **Fail closed on nothing.** A control-plane outage leaves the current peer set
  in place rather than tearing down live tunnels; access removal requires a
  successful poll that says so.
- **No private key handling.** Endpoints generate their own keys; this agent
  only ever sees public keys.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import logging
import os
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence, Set
from urllib import error as urlerror
from urllib import request as urlrequest

logger = logging.getLogger("olopa-sc-gateway")

VERSION = "1.0.0"
DEFAULT_INTERFACE = "olopa-gw0"
DEFAULT_INTERVAL_SECS = 15
DEFAULT_TIMEOUT_SECS = 10


class ReconcileError(RuntimeError):
    """A poll or apply step failed; the caller retries on the next tick."""


@dataclass(frozen=True)
class Peer:
    """One endpoint's desired presence on this gateway."""

    public_key: str
    allowed_ips: frozenset

    def allowed_ips_arg(self) -> str:
        return ",".join(sorted(self.allowed_ips))


@dataclass
class Plan:
    """Difference between desired and observed peer state."""

    add: List[Peer] = field(default_factory=list)
    update: List[Peer] = field(default_factory=list)
    remove: List[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.add or self.update or self.remove)

    def describe(self) -> str:
        return (
            f"add={len(self.add)} update={len(self.update)} remove={len(self.remove)}"
        )


@dataclass(frozen=True)
class Config:
    control_url: str
    gateway_id: str
    tenant_id: str
    api_token: str
    interface: str
    interval_secs: int
    timeout_secs: float
    dry_run: bool

    @classmethod
    def from_env(cls, args: argparse.Namespace) -> "Config":
        control_url = (args.control_url or os.getenv("OLOPA_GW_CONTROL_URL", "")).strip()
        gateway_id = (args.gateway_id or os.getenv("OLOPA_GW_GATEWAY_ID", "")).strip()
        if not control_url or not gateway_id:
            raise SystemExit(
                "OLOPA_GW_CONTROL_URL and OLOPA_GW_GATEWAY_ID are required "
                "(or pass --control-url/--gateway-id)"
            )
        if not control_url.startswith("https://") and not _env_flag(
            "OLOPA_GW_ALLOW_INSECURE_HTTP"
        ):
            raise SystemExit(
                "control URL must use https (set OLOPA_GW_ALLOW_INSECURE_HTTP=1 "
                "only for local development)"
            )
        return cls(
            control_url=control_url.rstrip("/"),
            gateway_id=gateway_id,
            tenant_id=(args.tenant_id or os.getenv("OLOPA_GW_TENANT_ID", "")).strip(),
            api_token=os.getenv("OLOPA_GW_API_TOKEN", "").strip(),
            interface=(
                args.interface
                or os.getenv("OLOPA_GW_INTERFACE", "")
                or DEFAULT_INTERFACE
            ).strip(),
            interval_secs=max(
                int(args.interval or os.getenv("OLOPA_GW_INTERVAL_SECS", 0) or 0)
                or DEFAULT_INTERVAL_SECS,
                1,
            ),
            timeout_secs=float(
                os.getenv("OLOPA_GW_TIMEOUT_SECS", "") or DEFAULT_TIMEOUT_SECS
            ),
            dry_run=bool(args.dry_run) or _env_flag("OLOPA_GW_DRY_RUN"),
        )


def _env_flag(key: str) -> bool:
    return os.getenv(key, "").strip().lower() in ("1", "true", "yes", "on")


# -- Desired state -------------------------------------------------------------


def _control_request(
    config: Config, path: str, *, method: str = "GET", body: Optional[dict] = None
) -> object:
    url = f"{config.control_url}/api/v1/secure-connect/{path}"
    payload = json.dumps(body).encode() if body is not None else None
    request = urlrequest.Request(url, data=payload, method=method)
    if payload is not None:
        request.add_header("content-type", "application/json")
    if config.api_token:
        request.add_header("authorization", f"Bearer {config.api_token}")
    if config.tenant_id:
        request.add_header("x-tenant-id", config.tenant_id)

    try:
        with urlrequest.urlopen(request, timeout=config.timeout_secs) as response:
            raw = response.read()
    except (urlerror.URLError, OSError) as exc:
        raise ReconcileError(f"control plane unreachable: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReconcileError(f"control plane returned invalid JSON: {exc}") from exc


def fetch_desired_peers(config: Config) -> List[Peer]:
    """Pull the peer set the control plane wants this gateway to serve."""
    payload = _control_request(config, f"gateways/{config.gateway_id}/peers")
    if not isinstance(payload, list):
        raise ReconcileError("control plane returned an unexpected peer payload")
    return parse_peers(payload)


def report_heartbeat(config: Config, observed_peers: int) -> None:
    """Tell the control plane this gateway is alive and converged.

    Silence is what triggers failover, so this is posted after every successful
    reconcile. A failed heartbeat is logged, never fatal: the gateway keeps
    serving traffic regardless.
    """
    try:
        _control_request(
            config,
            f"gateways/{config.gateway_id}/heartbeat",
            method="POST",
            body={
                "observed_peers": observed_peers,
                "reconciler_version": VERSION,
            },
        )
    except ReconcileError as exc:
        logger.warning("gateway heartbeat failed: %s", exc)


def parse_peers(payload: Sequence[dict]) -> List[Peer]:
    """Validate and normalise the peer list, dropping malformed entries."""
    peers: List[Peer] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        public_key = str(entry.get("public_key") or "").strip()
        allowed = entry.get("allowed_ips") or []
        if not public_key or not isinstance(allowed, list) or not allowed:
            logger.warning("skipping malformed peer entry: %s", entry)
            continue
        peers.append(
            Peer(
                public_key=public_key,
                allowed_ips=frozenset(str(item).strip() for item in allowed if item),
            )
        )
    return peers


# -- Observed state ------------------------------------------------------------


def run_command(args: Sequence[str]) -> str:
    """Run a command, returning stdout; raises `ReconcileError` on failure."""
    try:
        result = subprocess.run(
            list(args),
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise ReconcileError(f"failed to run {args[0]}: {exc}") from exc
    if result.returncode != 0:
        raise ReconcileError(
            f"{' '.join(args)} failed: {result.stderr.strip() or result.returncode}"
        )
    return result.stdout


def parse_wg_dump(dump: str) -> Dict[str, Set[str]]:
    """Parse `wg show <iface> dump` into `{public_key: allowed_ips}`.

    The first line describes the interface itself and is skipped; peer lines are
    tab-separated as `public_key, preshared_key, endpoint, allowed_ips,
    latest_handshake, rx, tx, keepalive`.
    """
    peers: Dict[str, Set[str]] = {}
    for index, line in enumerate(dump.splitlines()):
        if index == 0 or not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        public_key = fields[0].strip()
        allowed = {
            item.strip()
            for item in fields[3].split(",")
            if item.strip() and item.strip() != "(none)"
        }
        if public_key:
            peers[public_key] = allowed
    return peers


def observe_peers(config: Config) -> Dict[str, Set[str]]:
    return parse_wg_dump(run_command(["wg", "show", config.interface, "dump"]))


# -- Reconciliation ------------------------------------------------------------


def build_plan(desired: Iterable[Peer], observed: Dict[str, Set[str]]) -> Plan:
    """Compute the minimum set of `wg set` operations to converge."""
    plan = Plan()
    desired_by_key = {peer.public_key: peer for peer in desired}

    for public_key, peer in desired_by_key.items():
        current = observed.get(public_key)
        if current is None:
            plan.add.append(peer)
        elif current != set(peer.allowed_ips):
            plan.update.append(peer)

    for public_key in observed:
        if public_key not in desired_by_key:
            plan.remove.append(public_key)

    plan.remove.sort()
    return plan


def apply_plan(config: Config, plan: Plan) -> int:
    """Apply a plan with `wg set`; returns the number of operations performed."""
    operations = 0

    # Removals run first so a revoked key cannot linger while additions are
    # still being written.
    for public_key in plan.remove:
        _wg_set(config, ["peer", public_key, "remove"])
        logger.info("removed peer %s", _short_key(public_key))
        operations += 1

    for peer in plan.add + plan.update:
        _wg_set(
            config,
            ["peer", peer.public_key, "allowed-ips", peer.allowed_ips_arg()],
        )
        logger.info(
            "applied peer %s allowed-ips=%s",
            _short_key(peer.public_key),
            peer.allowed_ips_arg(),
        )
        operations += 1

    return operations


def _wg_set(config: Config, args: Sequence[str]) -> None:
    command = ["wg", "set", config.interface, *args]
    if config.dry_run:
        logger.info("[dry-run] %s", " ".join(command))
        return
    run_command(command)


def _short_key(public_key: str) -> str:
    return f"{public_key[:8]}..." if len(public_key) > 8 else public_key


def reconcile_once(config: Config) -> Plan:
    """One full cycle: pull desired state, observe local state, converge, report."""
    desired = fetch_desired_peers(config)
    observed = observe_peers(config)
    plan = build_plan(desired, observed)
    if plan.empty:
        logger.debug("gateway already converged (%d peers)", len(desired))
    else:
        logger.info("reconciling gateway: %s", plan.describe())
        apply_plan(config, plan)
    if not config.dry_run:
        report_heartbeat(config, len(desired))
    return plan


def run_loop(config: Config) -> int:
    logger.info(
        "olopa secure-connect gateway reconciler started interface=%s gateway=%s "
        "interval=%ss dry_run=%s",
        config.interface,
        config.gateway_id,
        config.interval_secs,
        config.dry_run,
    )
    while True:
        try:
            reconcile_once(config)
        except ReconcileError as exc:
            # Leave the existing peer set in place: an outage must not revoke
            # access on its own.
            logger.warning("reconcile failed, keeping current peers: %s", exc)
        except KeyboardInterrupt:
            logger.info("stopping")
            return 0
        try:
            time.sleep(config.interval_secs)
        except KeyboardInterrupt:
            logger.info("stopping")
            return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="olopa-sc-gateway",
        description="Reconcile a WireGuard gateway against Olopa Secure Connect",
    )
    parser.add_argument("--control-url", help="Control-plane base URL")
    parser.add_argument("--gateway-id", help="Gateway id registered in the control plane")
    parser.add_argument("--tenant-id", help="Tenant scope for the peer query")
    parser.add_argument("--interface", help=f"WireGuard interface (default {DEFAULT_INTERFACE})")
    parser.add_argument("--interval", type=int, help="Poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="Reconcile once and exit")
    parser.add_argument(
        "--dry-run", action="store_true", help="Print the plan without applying it"
    )
    parser.add_argument("--verbose", action="store_true", help="Debug logging")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = Config.from_env(args)

    if args.once:
        try:
            plan = reconcile_once(config)
        except ReconcileError as exc:
            logger.error("reconcile failed: %s", exc)
            return 1
        logger.info("reconcile complete: %s", plan.describe())
        return 0

    return run_loop(config)


if __name__ == "__main__":
    sys.exit(main())
