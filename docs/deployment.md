# Local Development and Deployment Notes

Osprey currently supports local development and single-instance use. The Compose setup runs the API with SQLite persistence and serves the static UI through Nginx, which proxies API requests to the backend. It binds host ports to loopback and requires configured authentication secrets. This is a local single-instance setup, not a production-hardened deployment.

## Docker Compose

Set `SECRET_KEY` (at least 32 bytes) and `AUTH_USERS_JSON` in an untracked local `.env` file, then run:

```sh
docker compose up --build
```

Open `http://127.0.0.1:8080`. API documentation is available at `http://127.0.0.1:8000/api/docs`. State is kept in the `osprey_state` Docker volume. PostgreSQL, Redis, and Neo4j are not started because the current backend does not use them. Compose does not mount a host project directory for workspace scanning; upload an SBOM or run the CLI directly against a local project.

## Backend

From the repository root:

```powershell
python -m pip install -r .\backend\requirements.txt
cd backend
python -m uvicorn guardianos.api.app:app --host 127.0.0.1 --port 8000
```

Set these environment variables before starting:

- `SECRET_KEY`: at least 32 bytes; required at production application startup.
- `AUTH_USERS_JSON`: JSON map of configured usernames to PBKDF2-SHA256 password hashes and roles.
- `STATE_DB_PATH`: SQLite file path; defaults to `./osprey-state.sqlite3`.
- `WORKSPACE_ROOT`: optional root allowed for local manifest scans; defaults to the backend process working directory.
- `ENABLE_DEMO_FIXTURES`: keep false unless running the explicitly simulated demo.

The SQLite file may contain inventory metadata, findings, evidence metadata/hashes, endpoint assertions, remediation proposals, upstream inputs, and audit events. Protect it as application data and back it up using normal SQLite-safe procedures. The NetworkX graph is in-memory and is rebuilt from stored inventory on startup.

## Frontend

```powershell
cd frontend
npm ci
npm run dev
```

For build validation, run `npm run build`. The project has no automated frontend test suite.

## CLI

```powershell
python -m pip install -e .\osprey
osprey scan .
osprey scan . --offline
```

The scanner reads supported files and never executes target code. Review the scan root and network settings before scanning untrusted repositories.

## Production readiness gaps

This repository is not a production-hardened multi-tenant service. It has no OIDC integration, rate limiting, multi-process SQLite deployment design, database migrations, durable graph adapter, external audit sink, runtime/cloud collectors, or complete frontend security test suite. Use a reverse proxy, private network, least-privilege filesystem mounts, managed secrets, and an external identity provider before exposing a deployment; those controls are not supplied by this project today.
