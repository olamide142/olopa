# Olopa Web Backend (FastAPI)

Waitlist API and platform boilerplate. Serves the landing page and `/api/v1/waitlist`.

## Setup

```bash
cd web/backend
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
cp .env.example .env
```

## Run

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- **Landing page:** http://localhost:8000/
- **Health:** http://localhost:8000/health
- **Waitlist:** POST http://localhost:8000/api/v1/waitlist (JSON: `email`, optional `name`, `company`)
- **Count:** GET http://localhost:8000/api/v1/waitlist/count

SQLite DB is created at `./olopa_waitlist.db` on first request.

## Env (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./olopa_waitlist.db` | DB connection |
| `CORS_ORIGINS` | `*` | Comma-separated origins |
| `WAITLIST_RATE_LIMIT_PER_HOUR` | `5` | Max signups per IP per hour |
