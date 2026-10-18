# AccessDrift — Zero-Trust Continuous Identity Governance

> **Continuous Identity Entitlement Drift Detection & Zero-Trust Governance**  
> IBM Z Datathon · Track 2 (AI Secured) · Track 1 (Real-Time AI)  
> Target Platform: **IBM LinuxONE (s390x)** & IBM Z Mainframe Cloud

[![Python 3.11 - 3.14](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green)](https://fastapi.tiangolo.com)
[![Memory](https://img.shields.io/badge/RAM-~50MB-brightgreen)](/)
[![Platform](https://img.shields.io/badge/platform-s390x%20%7C%20x86__64-orange)](/)

---

## Table of Contents

1. [What is AccessDrift?](#1-what-is-accessdrift)
2. [Demo Credentials](#2-demo-credentials)
3. [Quick Launch — Local Development](#3-quick-launch--local-development)
   - [Windows PowerShell](#windows-powershell)
   - [Linux / macOS](#linux--macos)
4. [Production Launch — IBM LinuxONE (s390x)](#4-production-launch--ibm-linuxone-s390x)
   - [Prerequisites on LinuxONE](#prerequisites-on-linuxone)
   - [1-Step Install and Run](#1-step-install-and-run)
   - [Manual Step-by-Step](#manual-step-by-step)
   - [Running as a Systemd Service](#running-as-a-systemd-service)
5. [Containerized Deployment — Docker & Docker Compose](#5-containerized-deployment--docker--docker-compose)
   - [Multi-Architecture Docker Build](#multi-architecture-docker-build)
   - [Running with Docker](#running-with-docker)
   - [Running with Docker Compose](#running-with-docker-compose)
6. [Port Forwarding & Remote Access](#6-port-forwarding--remote-access)
   - [SSH Local Port Forwarding](#ssh-local-port-forwarding-recommended)
   - [Direct Firewall / Security Group Access](#direct-firewall--security-group-access)
   - [Public Tunnel for Evaluators (Cloudflare Tunnel / ngrok)](#public-tunnel-for-evaluators)
7. [IBM Z Datathon Submission Guide](#7-ibm-z-datathon-submission-guide)
8. [Running the Test Suite](#8-running-the-test-suite)
9. [Repository Structure](#9-repository-structure)
10. [API Reference](#10-api-reference)
11. [Core Platform Capabilities](#11-core-platform-capabilities)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What is AccessDrift?

In enterprise environments employees accumulate privileges as they move between roles (*e.g. Software Engineer to Engineering Manager*) without shedding legacy permissions. This **privilege creep / entitlement drift** creates dormant superuser accounts, inflates attack surfaces, and violates zero-trust mandates (SOC2, ISO 27001, HIPAA).

**AccessDrift** is an AI-powered security governance platform that:
- Continuously audits enterprise permission matrices with **Isolation Forest ML** (ROC-AUC 0.972, F1 0.8697)
- Visualises entitlement drift as an interactive **force-directed topology graph**
- Generates **1-click dual remediation** — AWS IAM JSON policy + IBM Z RACF commands
- Maintains a **tamper-evident SHA-256 / CPACF blockchain audit ledger**
- Runs in **~50 MB RAM** — leaving >3.5 GB free on a 4 GB LinuxONE budget

---

## 2. Demo Credentials

### Presentation Demo Account (full dataset preloaded)

| Field | Value |
|:------|:------|
| **Username** | `trail_demo_ceo` |
| **Password** | `trail_demo` |
| **Persona** | Victoria Sterling — CISO / CEO |
| **Access Level** | `EXECUTIVE` — all features unlocked |

> Logging in with these credentials immediately loads the **36-employee enterprise demo dataset** across 5 global branches with pre-computed ML risk scores, topology graph, and blockchain audit ledger.

### Any Other Login → Blank Workspace

Any other username / password combination creates a **fresh blank enterprise workspace** where you define your own branch and add employees manually or via CSV. The password is set on first use.

### Pre-configured Evaluator Accounts

| Role | Username | Password | Persona |
|:-----|:---------|:---------|:--------|
| `EXECUTIVE` | `ceo` | `AccessDrift@Executive2026!` | Victoria Sterling |
| `ADMIN` | `admin` | `AccessDrift@Admin2026!` | Sarah Connor |
| `SECURITY_ANALYST` | `analyst` | `Analyst@Drift2026!` | Alex Mercer |
| `AUDITOR` | `auditor` | `Audit@Compliance2026!` | Marcus Vance |

---

## 3. Quick Launch — Local Development

### Windows PowerShell

```powershell
# 1. Clone the repository
git clone https://github.com/<your-org>/IBMZ-accessdrift.git
cd IBMZ-accessdrift

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install backend dependencies
pip install -r backend/requirements.txt

# 4. Launch the dev server (auto-reload enabled)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Open **http://127.0.0.1:8000** — the login screen appears.

> **Note:** If you see a script execution policy error, run first:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

---

### Linux / macOS

```bash
git clone https://github.com/<your-org>/IBMZ-accessdrift.git
cd IBMZ-accessdrift
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python -m unittest discover backend/tests
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 4. Production Launch — IBM LinuxONE (s390x)

AccessDrift is optimised for **IBM LinuxONE** (s390x) and automatically activates **IBM Z CPACF hardware acceleration** for AES-GCM encryption and SHA-256 hashing in the audit ledger. No configuration is required — the crypto vault detects the hardware at startup.

### Prerequisites on LinuxONE

| Requirement | Minimum Version | Check |
|:-----------|:----------------|:------|
| Python | 3.11, 3.12, or 3.14 | `python3 --version` |
| pip | Latest | `pip3 --version` |
| git | Any | `git --version` |
| OpenSSL | 3.x | Included in all modern distros |

```bash
# Ubuntu / Debian (LinuxONE Community Cloud default)
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv git

# RHEL / CentOS Stream / Fedora
sudo dnf install -y python3 python3-pip python3-venv git
```

> **CPACF Auto-Detection:** The platform shows crypto mode in the header bar:
> - `CPACF AES-GCM/SHA-256 Accelerated` on real s390x hardware
> - `OpenSSL AES-GCM/SHA-256 (Software)` on x86_64 fallback
>
> Both modes are functionally identical — hardware mode is faster and is the showcase feature.

---

### Docker Compose Deployment (Recommended for LinuxONE)

```bash
# Clone the repository
git clone https://github.com/arvind-harish-746/IBMZ-accessdrift.git
cd IBMZ-accessdrift

# Build with BuildKit and launch via Docker Compose
export DOCKER_BUILDKIT=1
docker compose build
docker compose up -d

# Verify container health and logs
docker compose ps
docker compose logs -f accessdrift
```

The Docker container runs with an unprivileged non-root user (`appuser:10001`), hardened multi-stage build, and auto-detects CPACF hardware acceleration on `s390x`.

> The UI is served directly by FastAPI at `http://<linuxone-ip>:8000` — **no separate web server (nginx/apache) or frontend build step required**.

---

### Manual Step-by-Step

```bash
# Step 1 — Clone
git clone https://github.com/arvind-harish-746/IBMZ-accessdrift.git
cd IBMZ-accessdrift

# Step 2 — Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Step 3 — Install dependencies
pip install --upgrade pip
pip install -r backend/requirements.txt

# Step 4 — Verify installation (optional but recommended)
python -m unittest discover -s backend/tests -v
# Expected: Ran 21 tests in ~4s — OK

# Step 5 — Launch
python -m uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --proxy-headers \
    --log-level info
```

**Access endpoints:**

| URL | Description |
|:----|:------------|
| `http://localhost:8000` | Web dashboard (from the machine) |
| `http://<machine-ip>:8000` | Web dashboard (from the network / judges) |
| `http://<machine-ip>:8000/docs` | Interactive Swagger API explorer |
| `http://<machine-ip>:8000/api/v1/system/health` | Health check JSON |

---

### Running as a Systemd Service

For persistent operation across reboots on LinuxONE:

```bash
# 1 — Create the service unit file
# Replace <your-linux-user> with your actual username (e.g. ubuntu, ibmz-user)
sudo tee /etc/systemd/system/accessdrift.service > /dev/null << 'EOF'
[Unit]
Description=AccessDrift Zero-Trust IAM Governance
After=network.target

[Service]
Type=simple
User=<your-linux-user>
WorkingDirectory=/home/<your-linux-user>/IBMZ-accessdrift
ExecStart=/home/<your-linux-user>/IBMZ-accessdrift/.venv/bin/uvicorn backend.main:app \
          --host 0.0.0.0 \
          --port 8000 \
          --workers 1 \
          --log-level info
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1

[Install]
WantedBy=multi-user.target
EOF

# 2 — Enable and start
sudo systemctl daemon-reload
sudo systemctl enable accessdrift
sudo systemctl start accessdrift

# 3 — Check status
sudo systemctl status accessdrift

# 4 — Follow live logs
sudo journalctl -u accessdrift -f
```

**Service management quick reference:**

```bash
sudo systemctl stop accessdrift      # Stop
sudo systemctl restart accessdrift   # Restart after code changes
sudo systemctl disable accessdrift   # Remove from auto-start
```


---

## 5. Containerized Deployment — Docker & Docker Compose

AccessDrift includes a production-grade multi-architecture Dockerfile tested for both **`linux/amd64`** and **`linux/s390x` (IBM LinuxONE)**.

### Key Docker Features:
- **Zero-Trust Non-Root Execution:** Runs under an unprivileged `appuser` system account.
- **Embedded Automated Verification:** Pre-flight test suite executes during image build.
- **Micro Footprint:** Consumes `< 60MB RAM` in production.
- **Built-in Healthcheck:** Integrated curl health probe against `/api/v1/system/health`.

---

### Running with Docker

#### 1. Build the Docker Image

```bash
docker build -t accessdrift:latest .
```

*For multi-architecture build targeting IBM LinuxONE (`s390x`) from x86_64 host:*
```bash
docker buildx build --platform linux/s390x,linux/amd64 -t accessdrift:latest .
```

#### 2. Run the Container

```bash
docker run -d \
  --name accessdrift \
  -p 8000:8000 \
  --restart unless-stopped \
  accessdrift:latest
```

#### 3. Verify Container Status & Logs

```bash
# Check container status & healthcheck
docker ps

# Stream application logs
docker logs -f accessdrift

# Test live API health
curl -s http://localhost:8000/api/v1/system/health
```

---

### Running with Docker Compose

A pre-configured [`docker-compose.yml`](file:///d:/Projects/IBMZ-accessdrift/docker-compose.yml) is included:

```bash
# Start in background
docker compose up -d

# Check service logs
docker compose logs -f

# Stop service
docker compose down
```

---

## 6. Port Forwarding & Remote Access

When deploying AccessDrift inside a Docker container on an **IBM LinuxONE Community Cloud** virtual machine, use one of the following methods to access the web dashboard:

### Method A — SSH Local Port Forwarding (Recommended & Most Secure)

If your IBM LinuxONE VM has a private IP or the cloud firewall blocks port 8000, forward port 8000 through your existing SSH connection:

```bash
# Run this on your LOCAL laptop / development machine:
ssh -L 8000:localhost:8000 <linuxone-user>@<linuxone-ip-or-hostname>
```

- Example: `ssh -L 8000:localhost:8000 ubuntu@148.100.xxx.xxx`
- Open your browser locally at: **`http://localhost:8000`**
- All web dashboard traffic is securely encrypted and routed directly to your LinuxONE instance.

### Method B — Direct Firewall & Security Group Access

If you want judges or team members to access the dashboard directly via the VM's public IP:

1. **Host Firewall Opening (inside the LinuxONE VM):**
   ```bash
   # Ubuntu / Debian
   sudo ufw allow 8000/tcp && sudo ufw reload

   # RHEL / CentOS Stream
   sudo firewall-cmd --permanent --add-port=8000/tcp && sudo firewall-cmd --reload
   ```

2. **Cloud Security Group Inbound Rule:**
   - In your IBM Cloud / LinuxONE Community Cloud console, go to **Network / Security Groups**.
   - Add an **Inbound Rule**: Protocol `TCP`, Port `8000`, Source `0.0.0.0/0` (or your specific IP).
   - Access directly at: **`http://<linuxone-ip>:8000`**.

### Method C — Public Tunnel for Evaluators (No Inbound Firewall Needed)

If your LinuxONE instance is behind strict NAT or VPN, you can expose a temporary public HTTPS link in 30 seconds:

```bash
# Option 1: Cloudflare Tunnel (Free, fast, no signup required)
curl -L --output cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-s390x
chmod +x cloudflared
./cloudflared tunnel --url http://localhost:8000

# Option 2: Localtunnel (via Node)
npx localtunnel --port 8000
```

Both tools generate a public HTTPS URL (e.g. `https://xxxx.trycloudflare.com`) that you can paste directly into your hackathon submission.

---

## 7. IBM Z Datathon Submission Guide

Follow this step-by-step checklist to ensure your submission is top-tier:

### Pre-Submission Quality Checklist

- [x] **21/21 Unit & Security Tests Pass:**
  ```bash
  python -m unittest discover -s backend/tests -v
  ```
- [x] **CPACF / Cryptographic Vault Active:**
  Verify `/api/v1/system/health` outputs `HEALTHY` and indicates CPACF acceleration on LinuxONE.
- [x] **RAM Budget Verified:**
  Memory consumption stays below **60 MB** (leaving >3.5 GB free on a 4 GB LinuxONE quota).
- [x] **Docker Image Builds & Runs:**
  Docker container starts and passes healthcheck without errors.
- [x] **Presentation Dataset Ready:**
  Preloaded with `trail_demo_ceo` (Victoria Sterling — CISO).

---

### Step-by-Step Submission Deliverables

When submitting on Devpost, HackerEarth, or the IBM Z submission portal, prepare the following 4 items:

#### 1. Public GitHub Repository Link
Ensure your repository is **public** and includes:
- Clean code structure (`backend/`, `frontend/`, `datasets/`)
- Production [`Dockerfile`](file:///d:/Projects/IBMZ-accessdrift/Dockerfile) and [`docker-compose.yml`](file:///d:/Projects/IBMZ-accessdrift/docker-compose.yml)
- Comprehensive [`README.md`](file:///d:/Projects/IBMZ-accessdrift/README.md) with architecture details and screenshots

#### 2. Live Demo URL / Evaluator Access
Provide evaluators with:
- **URL:** `http://<your-linuxone-ip>:8000` or Cloudflare Tunnel HTTPS link
- **Demo Credentials:**
  - Executive Persona: `trail_demo_ceo` / `trail_demo` (Preloaded enterprise dataset)
  - Admin Evaluator: `admin` / `AccessDrift@Admin2026!`
  - Blank Workspace: Any arbitrary new username & password

#### 3. 3-to-5 Minute Demo Video
Structure your video according to the winning pitch flow:
1. **The Problem (0:00 - 0:45):** Explain privilege creep / entitlement drift in enterprise hybrid clouds.
2. **Platform Architecture on LinuxONE (0:45 - 1:30):** Highlight s390x architecture, CPACF hardware cryptographic acceleration, and `<60MB RAM` footprint.
3. **Interactive Force Topology & ML Detection (1:30 - 2:45):** Log in as Victoria Sterling, show force-directed canvas, zoom in on Bob Vance's anomaly score and XAI feature contribution.
4. **1-Click Dual Remediation (2:45 - 3:30):** Click "Remediate", inspect the simultaneous **AWS IAM JSON** policy and **IBM Z RACF commands**.
5. **CPACF Blockchain Audit Ledger (3:30 - 4:00):** Open the tamper-evident ledger modal, show cryptographic hash chain verification.

#### 4. Architecture Pitch Deck / Summary
Include a short PDF slide deck or submission description covering:
- Track alignment (e.g. Track 1: Real-Time AI, Track 2: AI Secured)
- Machine Learning methodology: Isolation Forest ML pipeline (ROC-AUC 0.972, F1 0.8697)
- Dual remediation value proposition: Mainframe security (RACF) + Cloud IAM (AWS) in a single pane of glass.

---

## 8. Running the Test Suite

AccessDrift ships with **21 comprehensive tests** covering auth, ML inference, cryptography, and enterprise workflows.

```bash
# Activate the virtual environment first
source .venv/bin/activate        # Linux / macOS
.\.venv\Scripts\Activate.ps1     # Windows PowerShell

# Run all tests (verbose)
python -m unittest discover -s backend/tests -v

# Run a specific module
python -m unittest backend.tests.test_backend -v
python -m unittest backend.tests.test_ml_inference -v
```

Expected output:

```
test_auth.py              ...... 6/6  — JWT · PBKDF2 · RBAC enforcement · audit trail
test_enterprise_features  ...... 6/6  — trial login · CSV upload · branch filter · delete
test_ml_inference.py      .... 4/4  — Isolation Forest · features · score bounds · batch
test_backend.py           ..... 5/5  — CPACF vault · Bob Vance detection · 1-click remediation

----------------------------------------------------------------------
Ran 21 tests in 4.3s

OK
```

---

## 9. Repository Structure

```
IBMZ-accessdrift/
├── Dockerfile                # Multi-arch production container (linux/s390x & amd64)
├── docker-compose.yml        # 1-click container orchestration
├── .dockerignore             # Optimized build context filtering
├── backend/
│   ├── auth.py               # RFC 7519 JWT · PBKDF2 hashing · 4-tier RBAC · trial personas
│   ├── crypto.py             # CPACF / OpenSSL AES-GCM vault · SHA-256 blockchain ledger
│   ├── data_generator.py     # Enterprise roles · permissions · baselines · 5 regional branches
│   ├── engine.py             # Zero-safe cosine vector math · Isolation Forest anomaly engine
│   ├── main.py               # FastAPI gateway · REST endpoints · static frontend serving
│   ├── ml_service.py         # Scikit-learn Isolation Forest inference service
│   ├── models/
│   │   ├── accessdrift_isolation_forest.joblib   # Trained production ML pipeline
│   │   └── model_metadata.json                   # Feature schema · threshold · metrics
│   ├── remediation.py        # 1-click privilege pruner — AWS IAM JSON + IBM Z RACF
│   ├── requirements.txt      # Production Python dependencies
│   └── tests/
│       ├── test_auth.py
│       ├── test_backend.py
│       ├── test_enterprise_features.py
│       └── test_ml_inference.py
│
├── frontend/
│   ├── index.html            # SPA shell — all views and modals
│   ├── css/
│   │   ├── variables.css     # Design tokens · color palette · typography
│   │   ├── auth.css          # Google-style sign-in card
│   │   ├── layout.css        # Header · metrics ribbon · button system · responsive layout
│   │   ├── graph.css         # Force topology canvas · workspace grid · GPU acceleration
│   │   ├── inspector.css     # Identity inspector · XAI panel · remediation section
│   │   ├── modals.css        # Ingestion dialogs · role simulator · audit ledger modal
│   │   └── toast.css         # Toast notifications · employee data table
│   └── js/
│       ├── app.js            # Application coordinator · view routing · event wiring
│       ├── api.js            # Typed REST client for all backend endpoints
│       ├── state.js          # Central reactive state store
│       └── components/
│           ├── auth.js       # Sign-in / sign-out component
│           ├── graph.js      # HTML5 Canvas force-directed graph engine
│           ├── inspector.js  # Identity inspector · XAI breakdown · remediation
│           ├── modals.js     # Modal orchestration · CSV upload · ledger viewer
│           ├── onboarding.js # Blank workspace guided onboarding banner
│           ├── roster-table.js  # Employee directory table with role/risk filters
│           └── toast.js      # Toast notification utility · DOM escape helper
│
├── Dockerfile                # Hardened multi-stage build (s390x / IBM LinuxONE)
├── docker-compose.yml        # Orchestration with health checks & memory limits
├── frontend_propmt.md        # Frontend specification prompt used to build the UI
├── .gitignore
└── README.md
```

---

## 10. API Reference

| Method | Endpoint | Auth Required | Description |
|:-------|:---------|:-------------|:------------|
| `GET` | `/` | None | Serves the web dashboard UI |
| `GET` | `/docs` | None | Interactive Swagger API explorer |
| `POST` | `/api/v1/auth/login` | None | Username + password JWT sign-in |
| `GET` | `/api/v1/auth/me` | Bearer | Current session identity and RBAC profile |
| `GET` | `/api/v1/auth/presentation-personas` | None | Lists available 1-click demo personas |
| `POST` | `/api/v1/auth/trial-login` | None | Zero-password persona sign-in |
| `POST` | `/api/v1/auth/register-trial` | None | On-the-fly evaluator session creation |
| `GET` | `/api/v1/branches` | Bearer | Branches with employee counts and risk metrics |
| `GET` | `/api/v1/users` | Bearer | Scored roster with anomaly flags (`?branch=`) |
| `GET` | `/api/v1/users/{id}` | Bearer | Explainable AI risk breakdown for one employee |
| `GET` | `/api/v1/topology` | Bearer | Force-graph nodes and links (`?branch=`) |
| `POST` | `/api/v1/roster/add-user` | EXEC / ADMIN | Register employee and run ML scoring |
| `DELETE` | `/api/v1/roster/users/{id}` | EXEC / ADMIN | Remove employee from active roster |
| `GET` | `/api/v1/roster/csv-template` | None | Download pre-formatted IAM CSV template |
| `POST` | `/api/v1/roster/upload-csv` | EXEC / ADMIN | Batch CSV ingest with ML batch scoring |
| `POST` | `/api/v1/remediate` | EXEC / ADMIN | 1-click privilege pruning — dual policy output |
| `POST` | `/api/v1/simulate/role-change` | EXEC / ADMIN / ANALYST | Privilege creep simulation |
| `GET` | `/api/v1/audit-ledger` | EXEC / ADMIN / AUDITOR | SHA-256 CPACF blockchain ledger |
| `POST` | `/api/v1/reset` | EXEC / ADMIN | Restore pristine demo dataset |
| `GET` | `/api/v1/system/health` | None | RAM usage in MB and crypto hardware mode |

---

## 11. Core Platform Capabilities

| Capability | Detail |
|:-----------|:-------|
| **ML Anomaly Engine** | Scikit-learn Isolation Forest · 12 drift features · τ = 0.055 · ROC-AUC 0.9721 · F1 0.8697 |
| **Multi-Branch Governance** | Global HQ – New York · EMEA – London · APAC – Singapore · IBM Z Lab – Poughkeepsie · Latin America – São Paulo |
| **Dynamic Roster Ingestion** | Batch CSV upload or manual employee add · instant per-record ML scoring |
| **Topology Visualisation** | Pure HTML5 Canvas 60 FPS force-directed physics graph · no external library |
| **1-Click Dual Remediation** | Simultaneously prunes drift and generates AWS IAM JSON + IBM Z RACF mainframe commands |
| **CPACF Audit Ledger** | Immutable SHA-256 blockchain with CPACF hardware acceleration on s390x |
| **Zero-Infrastructure** | No database · no message broker · no build pipeline · ~50 MB RAM |

---

## 12. Troubleshooting

### Port 8000 already in use

```bash
# Linux / macOS
lsof -ti:8000 | xargs kill -9

# Windows
netstat -ano | findstr :8000
# Find the PID in the last column, then:
taskkill /PID <pid> /F
```

### Script execution policy error (Windows)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### `ModuleNotFoundError: No module named 'backend'`

Always run from the **project root** (the directory containing both `backend/` and `frontend/` folders):

```bash
cd /path/to/IBMZ-accessdrift
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### scikit-learn not found

```bash
pip install "scikit-learn>=1.5.0"
```

### CPACF shows "Software" mode

This is expected on x86_64 / Windows / macOS. CPACF acceleration only activates on genuine **IBM Z or LinuxONE (s390x) hardware**. All features work identically in software mode.

### Cannot access from another machine on LinuxONE

Open port 8000 in the firewall:

```bash
# Ubuntu / Debian
sudo ufw allow 8000/tcp && sudo ufw reload

# RHEL / Fedora
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload
```

### Verify the server is healthy

```bash
curl -s http://localhost:8000/api/v1/system/health | python3 -m json.tool
```

Expected response on LinuxONE:

```json
{
    "status": "HEALTHY",
    "crypto_mode": "CPACF AES-GCM/SHA-256 Accelerated",
    "memory_rss_mb": 48.7
}
`
