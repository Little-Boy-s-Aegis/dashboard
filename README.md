# Aegis SOC Dashboard

[![Git Clones](https://badgen.net/https/cdn.jsdelivr.net/gh/Little-Boy-s-Aegis/aegis-bank-deployment@main/dashboard-clone-badge.json)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment)
[![Unique Cloners](https://badgen.net/https/cdn.jsdelivr.net/gh/Little-Boy-s-Aegis/aegis-bank-deployment@main/dashboard-uniques-badge.json)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment)
[![Release Downloads](https://badgen.net/https/cdn.jsdelivr.net/gh/Little-Boy-s-Aegis/aegis-bank-deployment@main/downloads-badge.json)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment/releases)
[![Stars](https://badgen.net/github/stars/Little-Boy-s-Aegis/dashboard?color=f59e0b)](https://github.com/Little-Boy-s-Aegis/dashboard/stargazers)

Security Operations Center application for Little Boy's Aegis. A Go API ingests
and stores security events, coordinates analyst actions and SOAR decisions, and
serves a React/Vite interface for alerts, agents, logs, FIM, response actions,
metrics, and security simulations.

## Capabilities

- Real-time Kafka security-event consumption
- L0 log processing and enrichment for Layer 2
- PostgreSQL persistence with an in-memory development fallback
- OTP/session-based SOC operator authentication
- Alert search, assignment, analysis, bulk operations, and resolution
- Agent health and host resource visibility
- File Integrity Monitoring and log workbench views
- Response-center action execution and audit history
- Internal SOAR decision intake and automatic ban coordination
- Optional AWS WAF and network ACL synchronization
- Runtime simulation and seeding controls
- React dashboards for overview, agents, alerts, FIM, logs, SOAR performance,
  CloudWatch, response actions, and orchestrator interaction

## Architecture

```text
Kafka / bank API / SOAR
          |
          v
Go backend :8082
  |-- consumer + log processor
  |-- auth / alert / action handlers
  |-- PostgreSQL or in-memory store
  `-- AWS WAF / NACL integrations
          ^
          | /api
React + Vite :3001 (base path /soc/)
```

The backend uses the Go standard-library HTTP server and `kafka-go`. The
frontend is a separate React 19 single-page application served under `/soc/`.
In the full stack, Nginx routes `/api/` to Go and `/soc/` to the frontend.

## Prerequisites

- Go version declared in `backend/go.mod`
- Node.js 20+ and npm
- Optional PostgreSQL 16; the backend falls back to in-memory state when it
  cannot connect
- Optional Kafka for live ingestion

## Local Development

### Start the backend

```bash
cd backend
go mod download
go run .
```

The API listens on <http://localhost:8082> by default. Verify it with:

```bash
curl http://localhost:8082/health
```

If PostgreSQL is unavailable, startup logs explicitly report in-memory mode.
That mode is suitable for UI development but loses state on restart.

### Start the frontend

In a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://localhost:3001/soc/>. Vite proxies `/api` to
`http://localhost:8082` during development.

## Backend Configuration

| Variable | Default / behavior | Purpose |
|---|---|---|
| `PORT` | `8082` | API listener |
| `DATABASE_URL` | local PostgreSQL DSN | Complete Postgres connection string |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | optional | Component-form database configuration |
| `KAFKA_BOOTSTRAP_SERVERS` | empty disables consumer paths | Kafka brokers |
| `FRONTEND_URL` | `http://localhost:5173` fallback | Allowed/default CORS origin |
| `AEGIS_INTERNAL_TOKEN` | empty | Internal dashboard, SOAR, and bank service authentication |
| `BANK_BACKEND_URL` | handler-specific local default | Spring Boot bank API |
| `AEGIS_COOKIE_SECURE` | automatic/override | Force secure session cookies |
| `AEGIS_SIMULATION_ENABLED` | `false` | Enable demo seeding/simulation |
| `AEGIS_AGENT_THREAT_WINDOW_MINUTES` | implementation default | Agent threat activity window |
| `AEGIS_ENFORCE_SOC_IP_BAN` | disabled unless enabled | Enforce SOC-side IP bans |
| `AWS_REGION` | AWS SDK default | WAF/NACL region |
| `AWS_WAF_IP_SET_NAME`, `AWS_WAF_IP_SET_ID` | optional | Regional WAF synchronization |
| `AWS_WAF_CLOUDFRONT_IP_SET_NAME`, `AWS_WAF_CLOUDFRONT_IP_SET_ID` | optional | CloudFront WAF synchronization |
| `AWS_NETWORK_ACL_ID` | optional | Network ACL synchronization |

Prefer `DATABASE_URL` over the component variables. Keep internal tokens and
database credentials out of the repository and shell history.

## API Overview

| Area | Endpoints |
|---|---|
| Health | `GET /health` |
| Authentication | `/api/auth/request-token`, `/login`, `/logout`, `/check` |
| Operators | `GET /api/operators` |
| Overview | `GET /api/summary` |
| Agents | `GET /api/agents`, `GET /api/agents/{id}` |
| Alerts | list/detail, analyze, save analysis, assign, resolve, bulk operations, orchestrated ban |
| Telemetry | `GET /api/logs`, `GET /api/fim` |
| Response | `GET/POST /api/actions`, `GET /api/banned-ips` |
| SOAR | `GET /api/soar/metrics`, `POST /api/internal/soar/decision` |
| Internal services | IP-ban check and latest-OTP endpoints |
| Settings | `GET/POST /api/settings` |
| Demo | `POST /api/simulate` when enabled |

Most routes pass through authentication and IP-ban middleware. Internal routes
require the synchronized Aegis token; do not expose them directly to the public
internet.

## Tests and Quality Checks

Backend:

```bash
cd backend
go test ./...
go vet ./...
```

Frontend:

```bash
cd frontend
npm run lint
npm test
npm run build
```

Repository-level Python scripts exercise login-attack and path-traversal
scenarios against a running API:

```bash
python3 test_login_attack.py
python3 test_path_traversal.py
```

Confirm their target URLs and run them only against an authorized local or
staging environment.

## Docker

Build the API from the repository root:

```bash
docker build -t aegis-dashboard-backend .
docker run --rm -p 8082:8082 \
  -e DATABASE_URL='postgres://postgres:<password>@host.docker.internal:5432/aegis?sslmode=disable' \
  aegis-dashboard-backend
```

Build the frontend from `frontend/`:

```bash
cd frontend
docker build -t aegis-dashboard-frontend .
docker run --rm -p 3001:3001 aegis-dashboard-frontend
```

The frontend image serves static assets at `/soc/`. Its Nginx configuration
does not proxy `/api`, so use the full Aegis gateway for an integrated
containerized deployment or add an external reverse proxy.

## Repository Layout

```text
backend/
├── consumer/       # Kafka ingestion
├── handlers/       # Auth, alert, SOAR, ban, WAF, and NACL HTTP logic
├── models/         # API and persistence structures
├── processor/      # L0 log enrichment/routing
├── store/          # PostgreSQL migrations and in-memory implementation
└── main.go         # Routes and middleware
frontend/
├── src/components/ # SOC views and tests
├── src/App.tsx     # Application shell/navigation
├── vite.config.ts  # /soc base path and dev proxy
└── Dockerfile      # Static Nginx image
Dockerfile          # Go backend image
```

## Security and Operations

- Disable `AEGIS_SIMULATION_ENABLED` in shared environments.
- Terminate TLS at the gateway and set secure-cookie behavior appropriately.
- Restrict internal endpoints and AWS permissions to the dashboard service
  identity.
- The backend sanitizes common secret terms and active tokens in logs, but logs
  should still be treated as sensitive.
- In-memory mode is intentionally permissive for development; use PostgreSQL
  for durable audit and operator state.
- WAF/NACL updates can change traffic flow. Test rollback and scope before
  enabling synchronization.

## Related Repositories

- [`aegis-bank-backend`](https://github.com/Little-Boy-s-Aegis/aegis-bank-backend) — source application and telemetry producer
- [`aegis-soar-engine`](https://github.com/Little-Boy-s-Aegis/aegis-soar-engine) — Layer 2 decisions and actions
- [`aegis-bank-deployment`](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment) — gateway and full stack
- [`aegis-bank-terraform`](https://github.com/Little-Boy-s-Aegis/aegis-bank-terraform) — AWS infrastructure
