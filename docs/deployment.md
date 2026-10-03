# GuardianOS v2 — Deployment Guide

GuardianOS supports both local native development and full containerized Docker Compose deployments.

## 1. Native Development Mode (No External Daemons Required)
GuardianOS is engineered with self-contained in-memory fallback capabilities (NetworkX Graph Store and SQLite persistence):

```bash
# 1. Run tests
python run_tests.py

# 2. Start Backend API
uvicorn guardianos.api.app:app --host 0.0.0.0 --port 8000 --reload

# 3. Start Frontend Dashboard
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 2. Production Multi-Container Deployment (Docker Compose)
For enterprise production environments with PostgreSQL and Neo4j:

```bash
docker compose up -d --build
```

### Services Deployed
- **backend**: FastAPI service on port 8000
- **frontend**: React Vite production build on port 80
- **postgres**: PostgreSQL 16 on port 5432
- **neo4j**: Neo4j Graph Database on ports 7474 and 7687
- **redis**: Redis 7.2 on port 6379
