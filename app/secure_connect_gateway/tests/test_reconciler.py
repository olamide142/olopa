"""Tests for the Secure Connect gateway reconciler."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

import reconciler
from reconciler import Config, Peer, ReconcileError


def config(**overrides) -> Config:
    base = dict(
        control_url="https://control.example",
        gateway_id="gw-1",
        tenant_id="default",
        api_token="token",
        interface="olopa-gw0",
        interval_secs=15,
        timeout_secs=5.0,
        dry_run=False,
    )
    base.update(overrides)
    return Config(**base)


def peer(key: str, *ips: str) -> Peer:
    return Peer(public_key=key, allowed_ips=frozenset(ips))


WG_DUMP = "\n".join(
    [
        "PRIVATEKEY\tGATEWAYPUB\t51820\toff",
        "PEER_A\t(none)\t203.0.113.9:1234\t10.90.0.2/32\t1700000000\t100\t200\t25",
        "PEER_B\t(none)\t203.0.113.8:1234\t10.90.0.3/32,10.90.0.4/32\t0\t0\t0\toff",
    ]
)


def test_wg_dump_parsing_skips_the_interface_line():
    parsed = reconciler.parse_wg_dump(WG_DUMP)
    assert set(parsed) == {"PEER_A", "PEER_B"}
    assert parsed["PEER_A"] == {"10.90.0.2/32"}
    assert parsed["PEER_B"] == {"10.90.0.3/32", "10.90.0.4/32"}


def test_wg_dump_parsing_tolerates_empty_and_short_lines():
    assert reconciler.parse_wg_dump("") == {}
    assert reconciler.parse_wg_dump("iface-line\n\nshort\tline\n") == {}


def test_plan_adds_updates_and_removes():
    desired = [peer("PEER_A", "10.90.0.2/32"), peer("PEER_C", "10.90.0.5/32")]
    observed = reconciler.parse_wg_dump(WG_DUMP)

    plan = reconciler.build_plan(desired, observed)

    assert [item.public_key for item in plan.add] == ["PEER_C"]
    assert plan.update == []
    # PEER_B is no longer authorised, so removing it is the revocation.
    assert plan.remove == ["PEER_B"]


def test_plan_updates_a_peer_whose_allowed_ips_changed():
    desired = [peer("PEER_A", "10.90.0.99/32")]
    observed = {"PEER_A": {"10.90.0.2/32"}}
    plan = reconciler.build_plan(desired, observed)
    assert plan.add == []
    assert [item.public_key for item in plan.update] == ["PEER_A"]
    assert plan.remove == []


def test_converged_state_produces_an_empty_plan():
    desired = [peer("PEER_A", "10.90.0.2/32")]
    observed = {"PEER_A": {"10.90.0.2/32"}}
    plan = reconciler.build_plan(desired, observed)
    assert plan.empty


def test_apply_removes_before_adding(monkeypatch):
    """A revoked key must not linger while new peers are still being written."""
    commands = []
    monkeypatch.setattr(reconciler, "run_command", lambda args: commands.append(list(args)) or "")

    plan = reconciler.Plan(
        add=[peer("NEW", "10.90.0.7/32")],
        update=[],
        remove=["OLD"],
    )
    assert reconciler.apply_plan(config(), plan) == 2
    assert commands[0] == ["wg", "set", "olopa-gw0", "peer", "OLD", "remove"]
    assert commands[1] == [
        "wg",
        "set",
        "olopa-gw0",
        "peer",
        "NEW",
        "allowed-ips",
        "10.90.0.7/32",
    ]


def test_dry_run_applies_nothing(monkeypatch):
    commands = []
    monkeypatch.setattr(reconciler, "run_command", lambda args: commands.append(list(args)) or "")

    plan = reconciler.Plan(add=[peer("NEW", "10.90.0.7/32")], remove=["OLD"])
    assert reconciler.apply_plan(config(dry_run=True), plan) == 2
    assert commands == []


def test_allowed_ips_are_sorted_for_stable_commands():
    assert peer("K", "10.0.0.2/32", "10.0.0.1/32").allowed_ips_arg() == (
        "10.0.0.1/32,10.0.0.2/32"
    )


def test_malformed_peer_entries_are_skipped():
    parsed = reconciler.parse_peers(
        [
            {"public_key": "GOOD", "allowed_ips": ["10.0.0.1/32"]},
            {"public_key": "", "allowed_ips": ["10.0.0.2/32"]},
            {"public_key": "NO_IPS", "allowed_ips": []},
            "not-a-dict",
        ]
    )
    assert [item.public_key for item in parsed] == ["GOOD"]


def test_control_plane_outage_raises_rather_than_clearing_peers(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(reconciler.urlrequest, "urlopen", boom)
    with pytest.raises(ReconcileError):
        reconciler.fetch_desired_peers(config())


def test_reconcile_loop_survives_a_failed_poll(monkeypatch, caplog):
    """An outage leaves the interface untouched instead of tearing tunnels down."""
    applied = []
    monkeypatch.setattr(
        reconciler,
        "fetch_desired_peers",
        lambda cfg: (_ for _ in ()).throw(ReconcileError("unreachable")),
    )
    monkeypatch.setattr(reconciler, "apply_plan", lambda cfg, plan: applied.append(plan))

    with pytest.raises(ReconcileError):
        reconciler.reconcile_once(config())
    assert applied == []


def test_insecure_control_url_is_rejected(monkeypatch):
    monkeypatch.delenv("OLOPA_GW_ALLOW_INSECURE_HTTP", raising=False)
    args = reconciler.build_parser().parse_args(
        ["--control-url", "http://control.example", "--gateway-id", "gw-1"]
    )
    with pytest.raises(SystemExit):
        Config.from_env(args)


def test_insecure_control_url_allowed_for_local_development(monkeypatch):
    monkeypatch.setenv("OLOPA_GW_ALLOW_INSECURE_HTTP", "1")
    args = reconciler.build_parser().parse_args(
        ["--control-url", "http://127.0.0.1:8100", "--gateway-id", "gw-1"]
    )
    assert Config.from_env(args).control_url == "http://127.0.0.1:8100"


def test_reconcile_reports_a_heartbeat_after_converging(monkeypatch):
    """Silence is what triggers failover, so a converged poll must report in."""
    monkeypatch.setattr(
        reconciler, "fetch_desired_peers", lambda cfg: [peer("PEER_A", "10.90.0.2/32")]
    )
    monkeypatch.setattr(reconciler, "observe_peers", lambda cfg: {"PEER_A": {"10.90.0.2/32"}})
    reported = []
    monkeypatch.setattr(
        reconciler, "report_heartbeat", lambda cfg, count: reported.append(count)
    )

    plan = reconciler.reconcile_once(config())
    assert plan.empty
    assert reported == [1]


def test_dry_run_does_not_report_a_heartbeat(monkeypatch):
    monkeypatch.setattr(reconciler, "fetch_desired_peers", lambda cfg: [])
    monkeypatch.setattr(reconciler, "observe_peers", lambda cfg: {})
    reported = []
    monkeypatch.setattr(
        reconciler, "report_heartbeat", lambda cfg, count: reported.append(count)
    )

    reconciler.reconcile_once(config(dry_run=True))
    assert reported == []


def test_a_failed_heartbeat_is_not_fatal(monkeypatch):
    """The gateway keeps serving traffic even if it cannot report in."""
    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(reconciler.urlrequest, "urlopen", boom)
    reconciler.report_heartbeat(config(), 5)  # must not raise


def test_fetch_parses_the_control_plane_peer_payload(monkeypatch):
    payload = json.dumps(
        [
            {
                "session_id": "s1",
                "device_id": "d1",
                "public_key": "PEER_A",
                "allowed_ips": ["10.90.0.2/32"],
                "expires_at_unix": 1700000000,
            }
        ]
    ).encode()

    class FakeResponse:
        def read(self):
            return payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(reconciler.urlrequest, "urlopen", lambda req, timeout: FakeResponse())
    peers = reconciler.fetch_desired_peers(config())
    assert peers == [peer("PEER_A", "10.90.0.2/32")]
