# Olopa: YC Application, Landing Page, Waitlist & Platform Boilerplate

**Product:** Olopa — AI-first security: describe policies in words; we scope your assets, generate policies, and deliver real-time risk scoring.  
**Target:** Y Combinator application + launch-ready web presence + FastAPI backend foundation.

---

## 0. AI-First Brand Positioning

**Core idea:** Anyone can describe security in plain language. Olopa scopes your resources and assets across network and devices, generates policies to mitigate threats, recommends the optimal approach to monitoring, and runs user behavioral analytics for **real-time risk scores**.

### One-liner (AI-first)
> **Olopa is AI-first security: describe your policy in words. We scope your assets across network and devices, generate policies to mitigate threats, optimize what we monitor, and score risk in real time.**

### Five pillars (use in landing, deck, YC)
1. **Verbal policy** — Anyone describes what they want (“No dev can read customer data from prod DB”; “Block uploads to personal cloud”). No YAML, no Rego by hand.
2. **Scope resources & assets** — We discover and map your resources and assets across network and devices so policies are grounded in what you actually have.
3. **Generate policies to mitigate threats** — From intent + asset scope, we generate enforceable policies (OPA/Rego, agent rules) that mitigate the threats you care about.
4. **Optimal monitoring** — We recommend what to monitor and where (not “collect everything”), so you get signal without noise or cost.
5. **User behavioral analytics → real-time risk score** — Behavior across users and endpoints feeds a live risk score so you see who and what is risky, in real time.

### How this fits the product
- **Under the hood:** eBPF + kernel visibility, policy engine (OPA), lineage, DLP — same technical moat.
- **Outward face:** “AI-first” = natural language in, scoped assets, generated policies, optimal monitoring, real-time risk. Technical depth is the *how*; verbal policy and risk score are the *what* users see.

---

## 1. YC Application Strategy

### One-liner (use everywhere — AI-first)
> **Olopa is AI-first security: you describe your policy in words. We scope your assets across network and devices, generate policies to mitigate threats, optimize monitoring, and deliver real-time user risk scores.**

### Why now
- **eBPF maturity:** Production-grade tooling (Cilium, Tetragon, Falco) proved the stack; market expects “eBPF-native” security.
- **Remote work + Shadow IT:** GenAI tools, personal cloud, unmanaged devices → need “who can do what” without invasive recording.
- **AI-first expectation:** Teams expect to describe intent in words and get policies + monitoring + risk, not hand-edit rules.
- **Incumbent weakness:** Aqua/Teramind are cloud-lifecycle or heavy agents; Olopa wins on **endpoint + legacy host** with verbal policy, asset scoping, and real-time risk.

### Traction to highlight (fill with real numbers)
- [ ] Waitlist signups (target: 100+ before application)
- [ ] Design partners / LOIs (2–3 security or platform teams)
- [ ] Open-source or prototype demos (e.g. minimal eBPF + policy demo)
- [ ] Technical validation: “We ran our agent at &lt;2% CPU overhead on 500 syscalls/sec”

### Application sections — key angles

| Section | Strategy |
|--------|----------|
| **Company name / idea** | Lead with “Machine Control Plane” and “observe first, enforce when proven.” |
| **What do you make?** | “AI-first security: you describe policies in words. We scope your assets across network and devices, generate policies to mitigate threats, recommend optimal monitoring, and run behavioral analytics for real-time risk scores. Under the hood: eBPF, policy engine, one lightweight agent.” |
| **Who are your customers?** | SecOps at mid-market/enterprise; DevOps/SRE who need “can’t touch prod DB from my laptop” without VPN theater. |
| **Why you?** | Deep systems/security (eBPF, kernel, policy); shipped security or infra before; understand both “ship fast” and “enterprise trust.” |
| **TAM** | Endpoint security + DLP + UEBA adjacent; cite markets (e.g. Gartner) and say “we take share from EDR + DLP + policy tools by unifying in one stack.” |
| **How do you make money?** | SaaS by seat/endpoint; optional modules (Observe / Enforce / Mesh / Compliance) as “feature cart”; usage-based for event volume. |
| **Competition** | Aqua (cloud), Teramind (DLP/UEBA), CrowdStrike (EDR). “We don’t replace EDR day one; we own the policy and data layer so you can enforce what you observe, with Cilium-level performance.” |

### Pre-application checklist
- [ ] One-liner on website and in first line of application
- [ ] 60-second demo video (observe → one policy → one block)
- [ ] Clear “Join waitlist” CTA and count (e.g. “Join 200+ security teams”)
- [ ] Founder LinkedIn/Twitter and short bios
- [ ] Design partner quotes or LOIs if available

---

## 2. Landing Page Strategy

### Goals
1. **Clarity in 5 seconds:** “AI-first security: describe in words → we scope, generate policies, and score risk in real time.”
2. **Trust:** Verbal policy + asset scoping + real-time risk; technical depth (eBPF, no proxy) as credibility, not headline.
3. **Conversion:** Email waitlist + optional “Request demo” for enterprises.

### Message hierarchy (AI-first)
1. **Headline:** e.g. “Describe your policy. We scope your assets, generate the rules, and score risk in real time.”
2. **Subhead:** “AI-first security across network and devices. No YAML, no Rego—just say what you want. We map your resources, create policies to mitigate threats, and monitor with real-time behavioral risk scores.”
3. **Proof points:** Verbal policy • Asset scoping • Threat mitigation • Optimal monitoring • Real-time risk score
4. **Social proof:** “Join X security teams on the waitlist” (dynamic count if possible)
5. **CTA:** “Join waitlist” (primary), “Request demo” (secondary)

### Sections (recommended)
- **Hero:** Headline, subhead (AI-first), one CTA (waitlist).
- **AI-first how it works:** 5 pillars — (1) Describe policy in words, (2) We scope resources & assets across network/devices, (3) We generate policies to mitigate threats, (4) Optimal approach to monitoring, (5) User behavioral analytics → real-time risk score.
- **Problem:** “Security tools are either noisy, slow, or require experts to write rules.”
- **How it’s different:** Table or bullets vs “Traditional tool” vs “Olopa” (policy authoring, monitoring, risk; plus DLP/network/privacy from README).
- **Waitlist:** Form (email + optional role/company) + “Get early access.”
- **Footer:** Links (Product, Docs, Privacy, Contact), copyright.

### Design direction
- **Tone:** Confident, technical-but-accessible, security-native.
- **Visual:** Dark or high-contrast optional; clean typography; avoid “AI slop” (generic gradients, Inter-only).
- **Tech cues:** Code snippets or architecture sketch only if they add clarity.

---

## 3. Join Waitlist Feature

### Requirements
- **Capture:** Email (required), optional: name, role, company, use case.
- **Validation:** Email format; rate limit per IP.
- **Storage:** Persistent (DB or sheet); no loss on restart.
- **Confirmation:** Optional “You’re on the list” page or email.
- **Privacy:** Short notice: “We’ll only email you about Olopa launch and early access.”

### User flow
1. User enters email (and optional fields) on landing page.
2. Submit → API validates → stores record.
3. Response: success message or inline error.
4. Optional: redirect to “Thanks, you’re on the list” page; optional email confirmation later.

### Data model (minimal)
- `email` (unique), `name`, `role`, `company`, `source` (e.g. "landing"), `created_at`, `ip_hash` (optional, for rate limit).

### Security
- Rate limit: e.g. 5 signups per IP per hour.
- No sensitive data; do not store plain IP (hash if needed).
- CORS only for your domain(s).

---

## 4. Platform Boilerplate (FastAPI)

### Purpose
- **Now:** Serve landing page (static), waitlist API, health check.
- **Later:** Console API, auth, ingest webhooks, policy API—without rewriting the app.

### Layout (aligned with README backend vision)

```
olopa/
  web/
    backend/                 # FastAPI app
      app/
        __init__.py
        main.py              # FastAPI app, CORS, routers
        config.py            # settings (env, feature flags)
        dependencies.py      # DB session, optional auth
        api/
          __init__.py
          v1/
            __init__.py
            router.py        # mounts v1 routes
            waitlist.py      # POST /waitlist, GET /waitlist/count
            health.py        # GET /health
        core/
          security.py        # rate limit, validation
          db.py              # session, base (SQLAlchemy or similar)
        models/
          waitlist.py        # WaitlistEntry model
        schemas/
          waitlist.py        # Pydantic request/response
      requirements.txt
      .env.example
    static/                  # built or copied frontend
    index.html               # landing (or SPA entry)
```

### API surface (v1)

| Method | Path | Purpose |
|--------|------|---------|
| GET | /health | Liveness/readiness |
| POST | /api/v1/waitlist | Submit waitlist (email + optional fields) |
| GET | /api/v1/waitlist/count | Public count for “Join N others” (cached 5 min) |

### Tech choices
- **FastAPI:** Async, OpenAPI, Pydantic.
- **DB:** SQLite for MVP (single file, no setup); switch to Postgres when needed (same SQLAlchemy model).
- **Config:** `pydantic-settings` from env + `.env`.
- **Rate limit:** `slowapi` or custom middleware per IP.

### Future-proofing
- Version from day one: `/api/v1/`.
- `tenant_id` or `org_id` in schema placeholders for multi-tenant later.
- Structured logging and request IDs for debugging.

---

## 5. Implementation Order

| Step | Task | Owner |
|------|------|--------|
| 1 | Write this plan (done) and get alignment on messaging | — |
| 2 | Implement FastAPI boilerplate + waitlist API + SQLite | Dev |
| 3 | Build landing page (HTML/CSS/JS) with waitlist form calling API | Dev |
| 4 | Add waitlist count to landing (“Join N others”) and optional thank-you page | Dev |
| 5 | Deploy (e.g. Fly.io / Railway / Vercel + one backend host) | Dev |
| 6 | Add analytics (optional), set up YC application draft | Founder |
| 7 | Drive waitlist (Twitter, HN, security communities), iterate copy from data | Founder |

---

## 6. Copy Snippets for Landing (AI-first)

- **Headline option A:** “Describe your policy. We scope your assets, generate the rules, and score risk in real time.”
- **Headline option B:** “AI-first security. Say it in words. We map your world, create the policies, and monitor risk live.”
- **Subhead:** “We scope resources and assets across network and devices, generate policies to mitigate threats, and use behavioral analytics for real-time risk scores. No YAML, no Rego—just describe what you want.”
- **CTA:** “Join the waitlist” / “Get early access”
- **Footer legal:** “We’ll only use your email for Olopa launch and early access. Unsubscribe anytime.”

---

## 7. YC Application Draft Snippets (paste-ready)

**One-liner (AI-first):**  
Olopa is AI-first security: you describe your policy in words. We scope your assets across network and devices, generate policies to mitigate threats, recommend optimal monitoring, and deliver real-time user risk scores.

**What we make:**  
An AI-first security platform: anyone describes what they want in plain language (“No dev can read prod customer data”; “Block uploads to personal cloud”). We scope their resources and assets across network and devices, generate enforceable policies to mitigate threats, recommend the optimal approach to monitoring (not “collect everything”), and run user behavioral analytics for real-time risk scores. Under the hood: eBPF, policy engine (OPA), one lightweight agent—observe first, enforce when ready.

**Why now:**  
eBPF is production-proven in Cilium and Falco; remote work and shadow IT (GenAI, personal cloud) created demand for “who can do what” that doesn’t rely on heavy agents or invasive recording. Incumbents own cloud or DLP; we own the endpoint and legacy host with one stack.

Use this plan to execute the landing page, waitlist, and FastAPI boilerplate in parallel where possible; ship the minimal slice first (landing + waitlist API), then layer on count and thank-you page.

---

## 8. Quick start (implemented)

- **Plan:** `web/PLAN_YC_LANDING_WAITLIST.md` (this file)
- **Landing page:** `web/index.html` — open from same origin as API or set `window.OLOPA_API_BASE = 'http://localhost:8000'` if frontend is on another port/host
- **Backend:** `web/backend/` — FastAPI app

```bash
cd web/backend
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Then open **http://localhost:8000/** — landing page and waitlist form are served from the same app; count and submit use `/api/v1/waitlist` and `/api/v1/waitlist/count`.
