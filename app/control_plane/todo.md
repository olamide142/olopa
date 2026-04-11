**Implementation Plan**

This file tracks the step-by-step build-out of the control plane router _and_ the shared service/`base` foundation before hooking real services into it.

### Step 0: Establish project layout
1. Add a `base/` package with `__init__.py` plus submodules for `middleware`, `rbac`, `auth`, `database`, `router`, and `di`/`providers`. Each module exports the shared abstractions described above.
2. Create `services/` directory with boilerplate founder modules:
   - `services/__init__.py` (service manifest / auto-discovery)
   - placeholder folder for each target service (`oil_banks`, `market`, `secure_connect`, `dashboard`)
3. Document the per-service module surface (`schema.py`, `models.py`, `service.py`, `resource.py`, `support/...` nodes) so onboarding is consistent.

### Step 1: Build base control-plane scaffolding
1. In `base/router.py`, implement a router builder that:
   - Reads service registry from `services.__all__` or dynamic folder scan.
   - Constructs a namespace-prefixed router (FastAPI Starlette, custom dispatch).
   - Applies global middleware (auth, RBAC guard, error handling).
2. In `base/middleware.py`, export decorators/hooks for operation interceptors; wire them into the router builder.
3. Implement `base/auth.py` and `base/rbac.py` for:
   - Extracting claims (JWT/Keycloak introspection) from requests.
   - Enforcing permission scopes/roles per handler using annotations or handler metadata.
4. Add `base/database.py` helpers to manage shared connection pool (asyncpg/sqlalchemy) and transaction context.
5. Introduce `base/providers.py` (a simple DI container) so services can register `support/providers` definitions.

### Step 2: Router + bootstrap integration
1. Create a `control_plane/__main__.py` (or equivalent entry point) that:
   - Loads config (ports, Keycloak URL, DB URIs).
   - Boots base router, attaches services, and starts the HTTP server.
2. Ensure router exposes health endpoint and metrics hook.
3. Add optional CLI or env-based switch to enable service sub-routers individually.

### Step 3: Scaffold first service (`secure_connect`)
1. Within `services/secure_connect`:
   - `schema.py`: define request/response payloads used by future handlers.
   - `models.py`: define ORM placeholders (Auth state, sessions, scopes).
   - `service.py`: implement `register(router, context)` that registers a sample endpoint, uses shared middleware, and returns metadata for RBAC.
   - `resource.py`: stub resource manager returning dummy data.
   - `support/errors.py`: base service error types.
   - `support/identity.py`: helper to deserialize Kc tokens and map to service roles.
   - `support/providers.py`: register config/provider objects with DI container.
2. Update base router to automatically mount `secure_connect` routes using its namespace.
3. Wire Keycloak (from docker-compose) to provide JWT for testing.

### Step 4+: Expand services incrementally
1. Copy secure_connect scaffolding to `oil_banks`, `market`, `dashboard`, wiring each to share the base surface forever.
2. Implement actual business logic (auth flows, data endpoints) per service once stable base is in place.
3. Continuously refine `base` capabilities (middleware, RBAC, DB sessions) as services demand more features.



  
