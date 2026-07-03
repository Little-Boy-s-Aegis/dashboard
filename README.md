# Aegis SOC Dashboard - AI-Native SIEM & Security Platform

Aegis SOC is a premium, real-time Security Operations Center (SOC) dashboard. It integrates telemetry visualization, automated cyberattack simulations, File Integrity Monitoring (FIM) diff triaging, and an AI Security Copilot playbook advisor.

## Architecture & Technology Stack
- **Frontend**: React 18, TypeScript, Vite, Vanilla CSS. Fully responsive design with glassmorphism, animated glow highlights, and custom SVG logs & alerts graphs.
- **Backend**: Go standard library REST API. Uses a thread-safe in-memory dataset, background event dispatch loop, and customizable security threat simulators.

## Features
1. **SOC Overview Dashboard**: Multi-indicator KPIs (threat score, agent counts, alarm trends, MITRE coverage mapping) and a prioritized **Top Affected Hosts** widget.
2. **Security Alerts Incident Manager**: Multi-severity triage grid (`OPEN`, `INVESTIGATING`, `RESOLVED`) supporting detail inspection, raw event JSON visualizers, and alarm resolution commands.
3. **AI Security Copilot**: Context-aware security analyst panel profiling malicious actors (e.g. LockBit 3.0), evaluating threat scopes, and recommending copyable CLI mitigation tasks.
4. **File Integrity Monitoring (FIM)**: Tracks host file creations, deletions, and config edits (e.g. `/etc/passwd` backdoor accounts or `/etc/security/limits.conf` sockets adjustments) side-by-side with an interactive color-coded diff inspector.
5. **Elastic Log Explorer**: Unified syslog console utilizing query matching and a real-time log hit frequency histogram.

---

## Quick Start

### Prerequisites
- Go 1.20+
- Node.js 18+

### 1. Launch the Backend API
```bash
cd backend
go run main.go
```
The Go REST backend will start listening on `http://localhost:8080`.

### 2. Launch the Frontend Dev Server
```bash
cd frontend
npm install
npm run dev
```
Open your browser and navigate to `http://localhost:5173/` (or `http://localhost:5174` if the port is offset) to interact with the platform.
