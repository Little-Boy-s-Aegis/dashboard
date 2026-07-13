# Aegis SOC Dashboard - SIEM & AI Security Copilot

The Aegis Security Operations Center (SOC) Dashboard is a real-time SIEM platform. It ingests security logs and telemetry produced by the banking backend, evaluates alerts using an AI Security Copilot, tracks host File Integrity Monitoring (FIM), and simulates security attack scenarios.

---

## Architecture & Stack
- **Go API Backend** (`dashboard/backend`): Uses Go Standard Library HTTP server, Segmentio Kafka-go reader, and PostgreSQL database with in-memory fallback.
- **Vite React Frontend** (`dashboard/frontend`): Built with React 19, TypeScript, Vite, Lucide icons, and HSL-styled vanilla CSS.

---

## Running the Dashboard (Direct / Host Mode)

To run the SOC dashboard locally, you must run the Go backend and React frontend concurrently:

### 1. Start the Go Backend API
Navigate to the `backend` folder, fetch dependencies, and run:
```bash
cd dashboard/backend
go mod download
go run main.go
```
- The SOC API server will start listening on **`http://localhost:8082`**.
- It automatically tries to connect to PostgreSQL. If PostgreSQL is offline, it gracefully falls back to **In-Memory database mode** so you can still explore the application.
- If `KAFKA_BOOTSTRAP_SERVERS` is set, it will read security logs from Kafka. Without that variable, Kafka ingestion is disabled and the backend still polls the bank security-log API.

### 2. Start the React Frontend Dev Server
In a separate terminal window:
```bash
cd dashboard/frontend
npm install
npm run dev
```
- Open **`http://localhost:3001`** in your browser.
- The Vite server is configured to proxy all `/api` requests to the Go backend on `http://localhost:8082`.

---

## Environment Variables (Go Backend)
Set these variables in your terminal to override default parameters:
- `DATABASE_URL`: Postgres DSN connection string (e.g. `postgres://postgres:1@localhost:5432/aegis?sslmode=disable`).
- `KAFKA_BOOTSTRAP_SERVERS`: Optional Kafka broker addresses for realtime security-event and L2 clean-log ingestion (e.g. `localhost:9094`).

---

## Containerized Deployment (Docker)

To run the dashboard services as isolated Docker containers:

### 1. Build & Run Go Backend
```bash
# From the 'dashboard' root directory
docker build -t aegis-dashboard-backend .

# Run container
docker run -d -p 8082:8082 \
  -e DATABASE_URL=postgres://postgres:1@host.docker.internal:5432/aegis \
  -e KAFKA_BOOTSTRAP_SERVERS=host.docker.internal:9094 \
  --name aegis-soc-backend-service \
  aegis-dashboard-backend
```

### 2. Build & Run React/Vite Frontend
```bash
# From the 'dashboard/frontend' directory
cd frontend
docker build -t aegis-dashboard-frontend .

# Run container
docker run -d -p 3001:3001 --name aegis-soc-frontend-service aegis-dashboard-frontend
```
The frontend container compiles the Vite project into static assets and uses internal Nginx to serve them on port `3001` under the `/soc/` path.

---

## SIEM Backend Hardening and Data Features

* **Dynamic Simulation & Seeding Controls**: Implemented dynamic seeding toggles in the Go API backend. Database auto-seeding and the threat activity simulator are now optional and controlled dynamically at runtime via the `AEGIS_SIMULATION_ENABLED` environment variable.
* **Go Backend Log Sanitization**: Added a custom `LogSanitizerWriter` wrapper around backend logging outputs to intercept and sanitize security-sensitive event logs, preventing internal credential/token disclosure.
* **Path Traversal & SOC Gateway Validation**: Integrated backend security validation tests ensuring API routing is secured against path traversal escapes and unauthorized SOAR gateway bypass actions.

---

## Tech Stack

| Component | Version |
|---|---|
| Go | 1.26 |
| Kafka-go | 0.4.51 (segmentio) |
| PostgreSQL driver | lib/pq 1.12.3 |
| AWS SDK | v2 (EC2, WAFv2) |
| React | 19.2.7 |
| Vite | 8.1.1 |
| TypeScript | 6.0.2 |
| Testing | Vitest 4.1.9, Testing Library |
| Docker Backend | golang:alpine multi-stage |
| Docker Frontend | node:20-alpine -> nginx:alpine |

---

## Deployment Info

In the full ecosystem, the Go backend runs as `dashboard-backend` on port 8082 and the React frontend runs as `dashboard-frontend` on port 3001. Nginx routes `/api/` to the backend and `/soc/` to the frontend. See [aegis-bank-deployment](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment) for the full setup.

---

## Related Repositories

| Repository | Description |
|---|---|
| [aegis-bank-deployment](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment) | Docker Compose orchestration |
| [aegis-bank-backend](https://github.com/Little-Boy-s-Aegis/aegis-bank-backend) | Spring Boot banking API |
| [aegis-bank-web-client](https://github.com/Little-Boy-s-Aegis/aegis-bank-web-client) | Next.js banking portal |
| [aegis-bank-mobile-app](https://github.com/Little-Boy-s-Aegis/aegis-bank-mobile-app) | Flutter mobile app |
| [agent-layer-1](https://github.com/Little-Boy-s-Aegis/agent-layer-1) | AI Sensor Agents |
| [agent-layer-2](https://github.com/Little-Boy-s-Aegis/agent-layer-2) | Meta Analyzer / SOAR Orchestrator prompts |
| [aegis-soar-engine](https://github.com/Little-Boy-s-Aegis/aegis-soar-engine) | SOAR Decision Engine |
| [aegis-staging-sandbox](https://github.com/Little-Boy-s-Aegis/aegis-staging-sandbox) | Staging Sandbox |
| [aegis-bank-terraform](https://github.com/Little-Boy-s-Aegis/aegis-bank-terraform) | Terraform IaC |
