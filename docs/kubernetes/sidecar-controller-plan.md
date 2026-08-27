# Kubernetes Agent, Sidecar, and Controller Plan

## Decision

Olopa should use three Kubernetes components with deliberately separate jobs:

1. A privileged **node agent DaemonSet** owns eBPF programs, kernel telemetry,
   enforcement maps, local spooling, and ingest delivery. There is one agent on
   each eligible Linux node.
2. An optional, unprivileged **workload sidecar** supplies application context
   and a local integration socket. It does not load eBPF programs or duplicate
   kernel collection.
3. An **Olopa controller** reconciles policy custom resources into versioned
   runtime-IR bundles, distributes them to node agents, reports rollout status,
   and later manages opt-in sidecar injection.

The controller is part of the Kubernetes product, but it is not required to
prove the first Kubernetes sensor deployment. Ship the DaemonSet and Helm chart
first, then add reconciliation once the node contract works on a real cluster.

## Why this shape

A sidecar-only sensor would attach overlapping eBPF programs for every pod,
consume much more memory, and still observe a node-shared kernel. The existing
agent already resolves a cgroup ID into a container ID and Kubernetes pod UID,
which is the correct starting point for attributing node events to workloads.

The missing pieces are Kubernetes metadata enrichment, container-safe host
path discovery, policy targeting, and a reconciler for compiled artifacts and
status. The OIL schema already exposes `k8s.workload`, and the runtime already
supports `baseline.workload(namespace, name)`.

## MVP boundary

The Kubernetes MVP proves this path:

> Install Olopa once, run one kernel sensor per eligible node, apply an OIL
> policy, and see pod-attributed telemetry without changing the workload.

Included:

- Linux node agent as a DaemonSet.
- Helm installation and upgrade.
- Runtime-IR supplied from a versioned ConfigMap.
- Ingest credentials supplied from a Secret.
- Pod UID, namespace, name, workload owner, and service-account enrichment.
- Health, readiness, deployment digest, and last-load-error status.
- A real-cluster smoke test against containerd.

Deferred from the first slice:

- Automatic sidecar injection.
- Namespaced and label-selective policy enforcement.
- Controller-managed compilation and rollback.
- CRI-O validation, multi-architecture images, and capability-minimized eBPF
  privileges.

## Component contracts

### Node agent DaemonSet

The DaemonSet runs the existing Rust agent with these additions:

- Use the host PID namespace so Unix peer credentials and uprobes resolve to
  host process IDs consistently.
- Mount `/sys/fs/bpf`, `/sys/kernel`, `/sys/fs/cgroup`, and the host `/proc`.
- Mount the host root read-only at `/host` for uprobe library discovery.
- Keep the delivery spool and callable-state checkpoint on a node-local
  `hostPath`, with a documented retention and size limit.
- Read the node name from the Downward API and watch only pods assigned to that
  node.
- Read the active runtime-IR bundle from a projected volume and atomically hot
  reload it after digest and schema validation.
- Expose HTTP health/readiness/metrics only inside the pod or through a
  ClusterIP Service intended for scraping.
- Continue using the last good runtime when a replacement is invalid.

The initial chart may use `privileged: true` because kernel and distribution
support varies. Hardening then narrows this to the capabilities actually needed
by the selected probes, such as `BPF`, `PERFMON`, `NET_ADMIN`, and `NET_RAW`,
with a documented fallback for older kernels. `hostNetwork` is enabled only
when XDP or TC attachment requires access to host interfaces; it is not a
default requirement for process telemetry.

Agent implementation work:

- Add `OLOPA_HOST_ROOT=/host` and consistently prefix host `/proc`, `/sys`, and
  dynamic-library discovery paths.
- Add a pod metadata cache keyed by pod UID. Store namespace, pod name, owner
  kind/name, labels, service account, node, and container IDs.
- Watch pods with `spec.nodeName=<current-node>` using a minimal, read-only
  service account.
- Add runtime bundle directory watching with a stable manifest format:
  `schema_version`, `generation`, `sha256`, `minimum_agent_version`, and the
  runtime-IR payload.
- Publish the loaded generation, digest, rule count, last error, and event/spool
  health for controller aggregation.
- Bind every event to the current pod UID metadata when available. Preserve the
  raw cgroup and container identifiers when Kubernetes metadata is absent.

### Optional workload sidecar

The sidecar is a bridge, not the kernel sensor. Its first useful responsibilities
are application-level context, tool or request annotations, and local status.

Contract:

- Run as non-root with a read-only root filesystem, no Linux capabilities, no
  host namespaces, and no Kubernetes API permissions.
- Receive pod name, namespace, UID, service account, and selected labels through
  the Downward API.
- Connect to the node agent over `/var/run/olopa/agent.sock`, mounted from a
  narrowly scoped host path.
- Use a versioned local protocol for heartbeats, application annotations, and
  future tool-call events.
- Let the node agent authenticate the peer from Unix credentials and map the
  peer PID/cgroup back to a pod UID. Claimed pod metadata is advisory and never
  the security boundary.
- Remain optional: node kernel telemetry must work for every pod without it.

Start with explicit sidecar configuration in a sample workload. Add automatic
injection only after the socket and identity contract are proven. Use a normal
long-running container initially; adopting Kubernetes native sidecar lifecycle
semantics can follow once the supported cluster-version floor is fixed.

### Olopa controller

Implement the controller as a small Rust service in `app/k8s_controller`, using
the Kubernetes Rust client and the existing `oilc` crates.

Responsibilities:

- Watch Olopa custom resources and the namespaces, pods, and nodes needed for
  targeting and status.
- Compile OIL into runtime-IR with the same compiler used by the control plane.
- Validate compatibility, calculate a SHA-256 digest, and publish an immutable,
  versioned bundle.
- Reconcile the active bundle reference without replacing a working bundle
  after a compile or validation failure.
- Aggregate node rollout state and set standard `Ready`, `Progressing`, and
  `Degraded` conditions.
- Use leader election so multiple replicas remain safe.
- Reconcile idempotently after restarts and tolerate temporary API or agent
  outages.
- Later host a mutating admission webhook for explicit, label-based sidecar
  injection.

The Kubernetes API is the desired-state source for the Kubernetes MVP. The
existing control plane may mirror and author these resources later, but there
must not be two independent policy registries. Runtime bundles remain compiler
outputs rather than user-edited resources.

## API design

Use `security.olopa.io/v1alpha1` while the contract is changing.

### `OlopaAgentConfig`

Cluster-scoped singleton controlling the installation:

- Agent and sidecar image references.
- Ingest URL and credential `Secret` reference.
- Enabled probe families and observe/enforce default.
- Node selector, tolerations, resources, priority class, and spool limit.
- Sidecar injection namespace and pod selectors.
- Status with observed generation, eligible/ready node counts, bundle digest,
  and conditions.

### `OlopaPolicy`

Namespaced policy content:

- OIL source or an immutable control-plane rule-version reference.
- `Observe` or `Enforce` mode.
- Compatibility requirements and optional expiry.
- Status with compiler diagnostics, runtime digest, observed generation, and
  conditions.

### `OlopaPolicyBinding`

Separates reusable policy content from targeting:

- Policy reference.
- Pod, namespace, node, and service-account selectors.
- Rollout strategy, percentage, and pause control.
- Status with matched pods/nodes, loaded agents, failures, and last good digest.

Cluster-wide policy content can be introduced later as `OlopaClusterPolicy`.
Avoid writing high-frequency per-node status into separate custom resources;
derive it from agent pods, metrics, and bounded controller status updates.

## Targeting model

The present agent loads one global runtime program. Preserve that limitation in
the first Kubernetes release: the ConfigMap policy applies to every eligible
node and the chart defaults to observe mode.

The next runtime-IR version adds policy targeting metadata. The agent evaluates
selectors against its pod cache before running a targeted rule or installing a
cgroup enforcement entry. Targeted rules fail closed as non-matches when pod
identity is unavailable; cluster-wide rules continue to work from kernel data.

Rollout percentages must use a deterministic hash of policy UID and pod UID so
the selected population is stable across controller restarts.

## Delivery phases

### K0 - Contracts and packaging

- Record the DaemonSet/controller/sidecar decision and versioned bundle format.
- Add multi-stage agent image builds and publish an immutable digest.
- Create `deploy/helm/olopa` with DaemonSet, RBAC, ConfigMap, Secret references,
  ServiceMonitor option, and hardened defaults.
- Add chart schema validation and rendered-manifest tests.

Exit: `helm install` places exactly one ready agent on each eligible Linux node.

### K1 - Kubernetes-aware node agent

- Implement host-root path handling and projected bundle hot reload.
- Implement node-scoped pod watching and metadata enrichment.
- Add health, readiness, metrics, and deployment-status reporting.
- Exercise process telemetry and durable delivery on a real cluster.

Exit: an execution inside a pod arrives with pod UID, namespace, workload
owner, service account, container ID, and node name.

### K2 - Controller and policy CRDs

- Scaffold `app/k8s_controller` and generated CRD schemas.
- Add controller Deployment, ServiceAccount, RBAC, and PodDisruptionBudget to
  the Helm chart.
- Reconcile `OlopaPolicy` compilation into immutable runtime bundles.
- Reconcile DaemonSet bundle activation and aggregate rollout status.
- Add leader election, last-good rollback, and finalizer-free deletion where
  possible.
- Keep cluster-wide observe mode as the only supported target in this phase.

Exit: a valid policy loads without restarting workloads; an invalid policy
reports diagnostics and leaves the last good program active.

### K3 - Workload targeting and enforcement

- Add targeting metadata to runtime-IR and the agent evaluator.
- Reconcile `OlopaPolicyBinding` selectors into deterministic pod/cgroup scope.
- Stage rollout through observe, canary, and enforce modes.
- Remove stale cgroup enforcement entries promptly on pod deletion.

Exit: a namespaced policy affects only matching pods, survives rescheduling,
and rolls back deterministically.

### K4 - Sidecar bridge

- Define the local socket protocol and implement the agent receiver.
- Add a minimal rootless sidecar and sample manually configured workload.
- Verify peer PID/cgroup identity and backpressure behavior.
- Add opt-in mutating webhook injection with namespace exclusions, reinvocation
  safety, TLS rotation, and `failurePolicy: Ignore` for the first release.

Exit: an opted-in pod receives exactly one sidecar, can emit application context,
and retains kernel telemetry when the sidecar is absent or unhealthy.

### K5 - Production hardening

- Replace broad privileges where supported and document the kernel matrix.
- Validate containerd and CRI-O, node drain/reboot, upgrades, mixed agent
  versions, network partitions, and API throttling.
- Add signed images, SBOMs, image policy guidance, resource dashboards, and
  operational runbooks.
- Add multi-architecture builds after the amd64 release is stable.

Exit: upgrade, rollback, disruption, and security tests pass on the supported
cluster matrix.

## Security and reliability requirements

- Use separate service accounts and RBAC for controller, node agent, and
  admission webhook. The sidecar gets no API access by default.
- Keep controller pods unprivileged and without host mounts.
- Restrict the node agent pod and its socket to selected nodes and namespaces.
- Store only credentials in Secrets; OIL source and compiled runtime-IR are not
  secrets.
- Never log bearer tokens, projected service-account tokens, raw SQL text, or
  unredacted application annotations.
- Pin images by digest in production and expose the running image and runtime
  bundle digests in status.
- Reject incompatible or corrupt bundles before activation and retain the last
  good bundle across restarts.
- Make admission optional and fail open initially so an Olopa outage cannot
  block unrelated workload deployment.
- Define resource requests and limits. Initial targets are 100m CPU/128 MiB for
  the controller and 25m CPU/32 MiB for an idle sidecar; measure the node agent
  before setting production limits.

## Verification matrix

Unit and fake-API tests:

- CRD defaulting, selector compilation, deterministic rollout selection, status
  transitions, retry behavior, and last-good activation.
- Pod UID/container mapping, owner resolution, host-path prefixing, and socket
  peer authentication.
- Admission idempotency, exclusion rules, and existing-sidecar handling.

Kind tests:

- Helm rendering/install, RBAC, controller reconciliation, policy diagnostics,
  rolling updates, and webhook injection.
- These tests prove Kubernetes behavior but do not replace live kernel tests.

Privileged Linux cluster tests:

- eBPF attach and event capture on supported kernels and container runtimes.
- Pod attribution through restart, reschedule, node drain, and node reboot.
- XDP/TC behavior where enabled, including cleanup of deleted pod cgroups.
- Spool recovery during ingest outages and policy rollback during controller
  outages.

## MVP acceptance criteria

1. `helm install` creates one ready agent per eligible Linux node.
2. An exec in a test pod appears in Olopa with correct node, namespace, pod,
   workload owner, service account, container, and cgroup identity.
3. A valid policy reaches every ready node within 60 seconds without restarting
   the test workload.
4. An invalid policy exposes compiler diagnostics and does not replace the last
   good runtime.
5. Agent and controller restarts converge without duplicate resources or lost
   active policy state.
6. Telemetry continues when no sidecar is installed.
7. In the sidecar phase, an opted-in pod receives exactly one sidecar and an
   excluded namespace receives none.

## Initial repository layout

```text
app/k8s_controller/          Rust reconciler and webhook
deploy/helm/olopa/           chart, CRDs, RBAC, and values
deploy/examples/kubernetes/  sample policies and workloads
agent/agent/src/             Kubernetes metadata and local socket modules
docs/kubernetes/             architecture and operator runbooks
```

The first implementation PR should cover K0 only. It establishes deployable
packaging and a stable agent/container contract without prematurely coupling
kernel bring-up to controller development.

## Kubernetes references

- [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
- [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/)
- [Custom resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [Sidecar containers](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
