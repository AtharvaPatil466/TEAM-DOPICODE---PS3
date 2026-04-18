# Infra

One-command bring-up for ShadowTrace (backend + frontend + lab).

## Quick start

```bash
# 1. Start the lab (creates the shadowlab network the backend attaches to).
cd lab && docker compose up -d

# 2. Build + start backend and frontend.
cd ../infra && docker compose up --build
```

- Frontend: http://localhost:8090
- Backend:  http://localhost:8000 (direct)
- Backend via nginx proxy: http://localhost:8090/api/... and /ws

## Pieces

- `backend.Dockerfile` — python:3.12-slim + nmap, non-root, uvicorn on :8000. SQLite persisted at `/app/data` via the `shadowtrace-data` volume.
- `frontend.Dockerfile` — multi-stage: node:20 builds Vite app, nginx:alpine serves it.
- `nginx.conf` — SPA fallback, proxies `/api/` and `/ws` to the backend service.
- `docker-compose.yml` — joins the external `lab_shadowlab` network so scans reach 172.28.0.0/24 without host bridge routing.

## Persistence

The backend DB lives in the `shadowtrace-data` named volume. `docker compose down` keeps it; `docker compose down -v` wipes it.

To load the demo freeze into the volume:

```bash
docker compose up -d backend
docker cp ../backend/shadowtrace-demo-freeze.db shadowtrace-backend:/app/data/shadowtrace.db
docker compose restart backend
```

## CI

`.github/workflows/ci.yml` runs on push/PR:
- backend: pip install + import smoke test
- frontend: `npm ci && npm run build`
- docker: builds both images (no push)
