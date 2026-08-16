"# olopa" 

> **New engineer?** Start with [engineering-onboarding.md](./engineering-onboarding.md) —
> it describes what is actually in the tree, how the components talk to each other, and how
> to build and test each one. The summary below is product framing, and some of the
> components it names are design intent rather than shipped code.

Based on the architecture documentation already loaded in this conversation, here's a clear summary:

---

## What is Olopa?

**Olopa is a next-generation, kernel-native security agent** designed for Linux environments. Its core purpose is to unify four previously separate security disciplines into a single, resource-efficient system:

| Discipline | What Olopa Does |
|---|---|
| **Runtime Telemetry** | Collects kernel-level security events with near-zero overhead using eBPF |
| **Agentic Firewall** | Intercepts and mediates every AI agent tool call in real time before it executes |
| **L4 Network Control** | Classifies and distributes connections at packet level before the kernel stack |
| **AI Policy Intelligence** | Learns normal behaviour, detects anomalies, and enforces OWASP LLM security standards |

### The Core Problem It Solves

Traditional security tools operate at a single layer — they either watch the network, or the kernel, or application calls, but never all three in a correlated way. Olopa's key insight is that **single events are not enough** — a real threat is a *chain*: read → classify → exfiltrate → egress. By correlating events from the kernel all the way up to AI agent tool calls in one system, Olopa can detect attack patterns that siloed tools would miss entirely.

### What Makes It Distinctive

- **Kernel authority** — because it runs inside the Linux kernel via eBPF, it cannot be bypassed or tampered with by user-space processes, containers, or applications
- **Built for AI agents** — the Agentic Firewall component is specifically designed to secure AI agent systems (MCP, REST tools, shell calls), making it one of the few security systems addressing the OWASP LLM Top 10 threat categories at runtime
- **Resource-aware** — uses an Operations Research scheduler (Multi-Dimensional Knapsack) to maximise security signal value under strict resource budgets, so it never competes with the workloads it protects
- **Privacy-preserving by default** — captures metadata rather than full payloads; full payload capture is opt-in and audited

### Technology Stack

Built in **Rust** (for the kernel agent) and **Python** (for the backend), with eBPF/XDP for kernel instrumentation, ClickHouse as the event analytics warehouse, and OPA (Open Policy Agent) for policy enforcement.

In short, Olopa is a security platform purpose-built for environments running AI agents, combining traditional runtime security with AI-native threat detection in a single kernel-rooted system.