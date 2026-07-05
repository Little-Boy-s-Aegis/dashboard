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
- It will attempt to read security logs from Kafka on `localhost:9094`.

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
- `KAFKA_BOOTSTRAP_SERVERS`: Kafka broker addresses (e.g. `localhost:9094`).

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
