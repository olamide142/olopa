"""Secure Connect orchestrator: server-side authority for managed WireGuard access.

The endpoint runtime lives in `agent/agent/src/secure_connect`; this package owns
enrollment, gateway assignment, policy compilation, key lifecycle, and the
risk-adaptive access state machine.
"""

# Intentionally no re-export of `router`: binding the APIRouter instance to the
# package attribute would shadow the `router` submodule.
