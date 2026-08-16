"""Risk-adaptive access state machine.

Restrictive transitions are automatic; relaxing ones need an operator, with a
single exception — `ELEVATED -> HEALTHY` after a clean cooldown window. The
agent enforces the same rule locally and drops any relaxation the server should
not have sent, so both sides must agree on the ordering.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Dict, Optional, Tuple

from sqlalchemy.orm import Session

from ..models.secure_connect import (
    RESTRICTION_RANK,
    ControlAction,
    SecureConnectSession,
    SessionState,
    as_utc,
    utc_now,
)

#: Risk actions from the profile model, in the plan's vocabulary.
RISK_ACTION_OBSERVE = "observe"
RISK_ACTION_STEP_UP_AUTH = "step_up_auth"
RISK_ACTION_RESTRICT = "restrict_to_safe_cidrs"
RISK_ACTION_QUARANTINE = "quarantine"
RISK_ACTION_TERMINATE = "terminate"

DEFAULT_RISK_ACTIONS: Dict[str, str] = {
    "low": RISK_ACTION_OBSERVE,
    "medium": RISK_ACTION_STEP_UP_AUTH,
    "high": RISK_ACTION_RESTRICT,
    "critical": RISK_ACTION_QUARANTINE,
}

_ACTION_TO_STATE: Dict[str, Optional[SessionState]] = {
    RISK_ACTION_OBSERVE: None,
    RISK_ACTION_STEP_UP_AUTH: SessionState.ELEVATED,
    RISK_ACTION_RESTRICT: SessionState.RESTRICTED,
    RISK_ACTION_QUARANTINE: SessionState.QUARANTINED,
    RISK_ACTION_TERMINATE: SessionState.TERMINATED,
}

_STATE_TO_COMMAND: Dict[str, ControlAction] = {
    SessionState.HEALTHY.value: ControlAction.NONE,
    SessionState.ELEVATED.value: ControlAction.NONE,
    SessionState.RESTRICTED.value: ControlAction.RESTRICT,
    SessionState.QUARANTINED.value: ControlAction.QUARANTINE,
    SessionState.TERMINATED.value: ControlAction.TERMINATE,
}


class TransitionRejected(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def command_for_state(state: SessionState) -> ControlAction:
    return _STATE_TO_COMMAND.get(state.value, ControlAction.NONE)


def target_state_for_severity(
    severity: str, risk_actions: Optional[Dict[str, str]] = None
) -> Optional[SessionState]:
    """Map an alert severity to the access state the profile asks for."""
    merged = {**DEFAULT_RISK_ACTIONS, **(risk_actions or {})}
    action = merged.get(severity.strip().lower())
    if action is None:
        return None
    return _ACTION_TO_STATE.get(action)


def is_relaxation(current: str, target: SessionState) -> bool:
    return RESTRICTION_RANK.get(target.value, 0) < RESTRICTION_RANK.get(current, 0)


def check_transition(
    session: SecureConnectSession,
    target: SessionState,
    *,
    operator_confirmed: bool = False,
    cooldown_secs: int = 0,
) -> None:
    """Raise `TransitionRejected` when a transition is not permitted."""
    current = session.state
    if current == SessionState.TERMINATED.value:
        raise TransitionRejected(
            "SESSION_TERMINATED",
            "Terminated sessions are terminal and require re-enrollment",
        )
    if not is_relaxation(current, target):
        return

    cooldown_ok = (
        current == SessionState.ELEVATED.value
        and target == SessionState.HEALTHY
        and _cooldown_elapsed(session, cooldown_secs)
    )
    if operator_confirmed or cooldown_ok:
        return
    raise TransitionRejected(
        "RELAXATION_REQUIRES_CONFIRMATION",
        f"Relaxing '{current}' to '{target.value}' requires operator confirmation",
    )


def _cooldown_elapsed(session: SecureConnectSession, cooldown_secs: int) -> bool:
    elevated_since = as_utc(session.elevated_since)
    if elevated_since is None:
        return False
    return utc_now() - elevated_since >= timedelta(seconds=cooldown_secs)


def queue_command(
    session: SecureConnectSession,
    action: ControlAction,
    desired_state: Optional[SessionState],
    reason: str,
) -> None:
    """Stage a command for the next heartbeat and start its latency clock."""
    session.pending_action = action.value
    session.pending_state = desired_state.value if desired_state else None
    session.pending_reason = reason[:256]
    session.pending_since = utc_now()


def apply_transition(
    db: Session,
    session: SecureConnectSession,
    target: SessionState,
    reason: str,
    *,
    operator_confirmed: bool = False,
    cooldown_secs: int = 0,
) -> bool:
    """Move a session to `target` and stage the matching endpoint command.

    Returns False when the session is already at or beyond `target`, so callers
    can stay idempotent under a repeating alert stream.
    """
    check_transition(
        session,
        target,
        operator_confirmed=operator_confirmed,
        cooldown_secs=cooldown_secs,
    )
    if session.state == target.value:
        return False

    session.state = target.value
    if target == SessionState.ELEVATED:
        session.elevated_since = utc_now()
    else:
        session.elevated_since = None
    if target == SessionState.TERMINATED:
        session.terminated_at = utc_now()
        session.close_reason = reason[:256]
    elif target == SessionState.QUARANTINED:
        session.close_reason = reason[:256]

    queue_command(session, command_for_state(target), target, reason)
    db.flush()
    return True


def evaluate_cooldown(
    session: SecureConnectSession, cooldown_secs: int
) -> Optional[Tuple[SessionState, str]]:
    """Return the healthy transition an elevated session has now earned."""
    if session.state != SessionState.ELEVATED.value:
        return None
    if not _cooldown_elapsed(session, cooldown_secs):
        return None
    return SessionState.HEALTHY, "clean posture window elapsed"
