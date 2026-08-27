# Olopa MVP

The MVP proves one product promise on one Linux endpoint:

> A kernel event is evaluated by a compiled OIL rule, delivered durably, and
> visible in an authenticated operator console.

It includes the OIL compiler, Linux agent, Rust ingest service, ClickHouse,
SurrealDB, the Python control plane, and the React console. Secure Connect,
fleet artifact delivery, graph execution, external OIDC, incident workflows,
and SQL query blocking remain outside the MVP boundary.

The first MVP is intentionally single-host. The Kubernetes follow-on uses a
node-agent DaemonSet, a policy controller, and an optional unprivileged workload
sidecar. See the [Kubernetes agent, sidecar, and controller plan](kubernetes/sidecar-controller-plan.md).

## Start the platform

Prerequisites are Docker with Compose, Rust stable, and Python 3. The first
build downloads container and language dependencies.

```bash
make mvp-up
make mvp-smoke
```

The Make targets use Docker's `default` context so a stopped Docker Desktop
context cannot shadow a running system daemon. Desktop-only installations can
set `OLOPA_MVP_DOCKER_CONTEXT=desktop-linux`.

Open `http://127.0.0.1:8100`. In the identity menu select **Dev token** and use:

```text
token: olopa-local-admin
tenant: default
```

The local defaults are deliberate development credentials, not production
secrets. Override them before starting the stack when the machine is shared:

```bash
export OLOPA_MVP_CONTROL_TOKEN='replace-me'
export OLOPA_MVP_INGEST_TOKEN='replace-me-too'
make mvp-up
make mvp-smoke
```

## Run the real sensor

The sensor needs Linux, Rust nightly with `bpf-linker`, and root or equivalent
BPF/network capabilities. It uses `oilc/src/rules/mvp_exec.oil`, which alerts on
process execution so the result is immediately visible during evaluation.

```bash
make mvp-agent
```

The launcher builds userspace and eBPF code before elevation, then runs only the
agent binary as root. Generate a visible event in another terminal with any new
process, for example `id`.

Set `OLOPA_IFACE`, `OLOPA_PROBE_EVENTS`, `OLOPA_RULE_SOURCE`, or
`OLOPA_INGEST_HOST_ID` to override launcher defaults.

## Operate the MVP

```bash
make mvp-logs
make mvp-down
```

`mvp-down` keeps database volumes. Use the regular `make down`/Docker volume
workflow only when intentionally resetting retained data.

## Acceptance criteria

The MVP is healthy when all of the following hold:

1. `make mvp-smoke` compiles `mvp_exec_seen` through the deployed control plane.
2. The ingest API accepts a versioned, authenticated batch.
3. The event appears through the authenticated control-plane telemetry API.
4. On a privileged Linux host, `make mvp-agent` attaches probes and new process
   events appear in the console.

## Kubernetes follow-on

The Kubernetes MVP preserves the same product proof while adding pod identity
and fleet rollout. The sensor runs once per Linux node as a DaemonSet. A
controller compiles and reconciles policies, and an optional sidecar adds
application context without loading its own eBPF programs.

Implementation proceeds in this order: Helm/DaemonSet packaging, Kubernetes
metadata in the node agent, policy CRDs and controller, workload targeting, and
then opt-in sidecar injection. The detailed plan defines the security boundary,
API shapes, phases, and acceptance tests.
