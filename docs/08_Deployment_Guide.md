# NetWatch AI — Deployment Guide

**Project:** NetWatch AI  
**Version:** 1.0  
**Status:** In Development  
**Deployment Model:** Local-first  
**Primary Environment:** Development / Laboratory  
**Cost:** Zero-cost using local and open-source software

---

# 1. Overview

NetWatch AI is designed primarily as a local network monitoring and security analytics platform.

The initial deployment does not require:

- Paid cloud infrastructure
- Paid APIs
- Commercial databases
- Commercial SIEM platforms
- Paid AI services

The complete system can run on a local computer or a controlled virtual laboratory environment.

---

# 2. Deployment Architecture

```text
                           Local Machine
                                |
                +---------------+---------------+
                |                               |
                v                               v
        React Frontend                     FastAPI Backend
        Vite Development Server                  |
                |                                |
                |                         +------+------+
                |                         |             |
                |                         v             v
                |                    SQLite DB     Processing
                |                                       |
                |                              +--------+--------+
                |                              |        |       |
                |                              v        v       v
                |                           Capture Detection ML
                |                              |
                |                              v
                |                         Network Interface
                |
                +---------- REST / WebSocket ----------+
````

---

# 3. Deployment Modes

## 3.1 Development Mode

Used during active development.

```text
React Dev Server
        +
FastAPI Development Server
        +
SQLite
        +
Local Network Interface
```

This is the recommended mode while building the application.

---

## 3.2 Production-Like Local Mode

A future local deployment may use:

```text
Built React Frontend
        +
FastAPI
        +
SQLite
        +
Local Network Interface
```

The frontend can eventually be served through a web server or by the backend.

---

## 3.3 Docker Mode

Docker support may be added after the application is stable.

Potential architecture:

```text
Docker Compose
│
├── frontend
├── backend
└── database
```

Packet capture permissions require additional host configuration and should therefore be treated as an optional deployment method rather than the first deployment path.

---

# 4. System Requirements

The exact resource requirements depend on network traffic and whether local AI is enabled.

Recommended development environment:

```text
Operating System:
Windows / Linux / macOS

Python:
3.11+

Node.js:
20+

RAM:
8 GB minimum
16 GB recommended when using local AI

Storage:
At least 5 GB free for development
More storage may be required for packet history and reports

CPU:
Modern multi-core CPU recommended
```

For packet capture, the user must also have appropriate permissions and a supported network capture driver.

---

# 5. Required Software

The initial project uses the following software.

## Backend

* Python
* FastAPI
* Uvicorn
* Scapy
* SQLAlchemy
* Pydantic
* Pandas
* NumPy
* Scikit-learn

## Frontend

* Node.js
* npm or pnpm
* React
* TypeScript
* Vite
* Tailwind CSS
* Recharts
* Lucide React

## Development

* Git
* GitHub
* VS Code

---

# 6. Project Structure

The intended repository structure is:

```text
NetWatch-AI/
│
├── backend/
│
├── frontend/
│
├── docs/
│
├── tests/
│
├── sample_data/
│
├── screenshots/
│
├── scripts/
│
├── README.md
├── .gitignore
├── .env.example
└── docker-compose.yml
```

The Figma Make export should initially remain inside:

```text
frontend/figma-design/
```

until the frontend architecture is refactored.

---

# 7. Clone the Repository

Example:

```bash
git clone https://github.com/<username>/NetWatch-AI.git
cd NetWatch-AI
```

Replace the repository URL with the actual GitHub repository.

---

# 8. Backend Setup

Navigate to the backend:

```bash
cd backend
```

---

# 9. Create Python Virtual Environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

The virtual environment isolates project dependencies from the system Python installation.

---

# 10. Install Python Dependencies

Once `requirements.txt` has been created:

```bash
pip install -r requirements.txt
```

Core dependencies are expected to include:

```text
fastapi
uvicorn
scapy
sqlalchemy
pydantic
pandas
numpy
scikit-learn
```

Additional dependencies may be added as implementation progresses.

---

# 11. Environment Configuration

The backend should use an environment file for configuration.

Example:

```text
backend/
├── .env
└── .env.example
```

Example `.env.example`:

```env
APP_NAME=NetWatch AI
APP_ENV=development
DATABASE_URL=sqlite:///./netwatch.db

HOST=127.0.0.1
PORT=8000

LOG_LEVEL=INFO

AI_ENABLED=false
AI_PROVIDER=local

PACKET_RETENTION_DAYS=30

DEFAULT_CAPTURE_INTERFACE=
```

The real `.env` file should not be committed to Git.

---

# 12. Database Initialization

The initial deployment uses SQLite.

Example database:

```text
backend/netwatch.db
```

The application should initialize the database when required.

Possible initialization process:

```text
Application Start
       |
       v
Database Connection
       |
       v
Check Schema
       |
       +---- Missing → Create Tables
       |
       +---- Exists → Continue
```

The final implementation should use a migration strategy once the schema becomes stable.

---

# 13. Run the Backend

From the `backend` directory:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected:

```text
Uvicorn running on http://127.0.0.1:8000
```

---

# 14. Verify Backend

Open:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

Alternative documentation:

```text
http://127.0.0.1:8000/redoc
```

The API documentation should be used to verify endpoints during development.

---

# 15. Frontend Setup

Open a second terminal.

Navigate to:

```bash
cd frontend
```

If the Figma Make export is currently stored in:

```text
frontend/figma-design/
```

the development server should initially be run from that project directory.

Example:

```bash
cd frontend/figma-design
```

---

# 16. Install Frontend Dependencies

Using npm:

```bash
npm install
```

Or using pnpm:

```bash
pnpm install
```

The package manager should match the lockfile used by the project where practical.

---

# 17. Run Frontend Development Server

Example with npm:

```bash
npm run dev
```

Example with pnpm:

```bash
pnpm dev
```

The development server will normally provide a local address such as:

```text
http://localhost:5173
```

---

# 18. Frontend-to-Backend Configuration

The frontend should use a configurable backend base URL.

Example:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

For WebSockets:

```env
VITE_WS_BASE_URL=ws://127.0.0.1:8000
```

The exact configuration mechanism should be finalized during frontend implementation.

---

# 19. Final Local Runtime

Once both services are running:

```text
Browser
   |
   | http://localhost:5173
   v
React Frontend
   |
   +---------- REST ----------+
   |                          |
   |                       FastAPI
   |                          |
   +------- WebSocket --------+
                              |
                    +---------+---------+
                    |         |         |
                    v         v         v
                 Capture   Detection  SQLite
                    |
                    v
              Network Interface
```

---

# 20. Network Capture Requirements

Packet capture requires access to a suitable network interface.

Possible interfaces include:

```text
Wi-Fi
Ethernet
VMnet
VirtualBox Host-Only
Loopback
```

The interface names depend on the host operating system.

The application should expose available interfaces through:

```text
GET /api/v1/capture/interfaces
```

---

# 21. Windows Packet Capture

On Windows, Scapy may require a packet capture driver such as Npcap.

The user should install the driver using its official installation process.

After installation:

```text
Network Interface
        |
        v
Packet Capture Driver
        |
        v
Scapy
```

The application may need to be run with elevated privileges depending on the capture configuration and Windows security settings.

---

# 22. Linux Packet Capture

On Linux, packet capture may require elevated privileges.

A controlled development setup may use:

```bash
sudo
```

or appropriate capabilities.

The exact permission model should be configured according to the distribution and security requirements.

The application should avoid running the entire system as root when a more restricted permission model is possible.

---

# 23. macOS Packet Capture

macOS may require appropriate packet-capture permissions depending on the interface and capture configuration.

The application should verify the interface and permission requirements before starting capture.

---

# 24. Controlled Security Testing Environment

The project should be tested using systems for which the user has authorization.

A suitable laboratory may contain:

```text
Host Machine
     |
     +---- Kali Linux VM
     |
     +---- Metasploitable VM
     |
     +---- NetWatch AI
```

This environment allows controlled testing of detection features.

---

# 25. Example Laboratory Flow

```text
Kali Linux
    |
    | Authorized Scan
    v
Test Target
    |
    v
Network Traffic
    |
    v
NetWatch AI
    |
    v
Port Scan Detection
    |
    v
Alert
    |
    v
Dashboard
```

The project should only be used to monitor and test systems for which authorization exists.

---

# 26. Starting Packet Capture

From the dashboard:

```text
Settings / Capture
       |
       v
Select Interface
       |
       v
Start Capture
```

The frontend sends:

```http
POST /api/v1/capture/start
```

Example:

```json
{
  "interface": "Wi-Fi"
}
```

---

# 27. Packet Processing Runtime

Once capture begins:

```text
Network Interface
       |
       v
Scapy
       |
       v
Packet Parser
       |
       v
Normalizer
       |
       v
Feature Extraction
       |
       +----------------+
       |                |
       v                v
Statistics         Detection
       |                |
       +--------+-------+
                |
                v
            Database
                |
                v
           WebSocket
                |
                v
           Dashboard
```

---

# 28. ML Deployment

ML inference runs locally.

Initial model:

```text
Isolation Forest
```

Model files may be stored under:

```text
backend/
└── models/
    └── anomaly_detector/
```

The application should load the model when the ML service starts.

If the model is unavailable:

```text
ML Engine:
Unavailable
```

Core packet capture and rule detection should continue.

---

# 29. Local AI Deployment

Local AI is optional.

A possible implementation uses:

```text
Ollama
   |
   v
Local Language Model
   |
   v
AI Analysis Service
```

The AI engine should not be required for the core monitoring system.

Example:

```text
AI Enabled = false

Packet Capture     ✓
Statistics         ✓
Rules              ✓
Behavior           ✓
ML                 ✓
AI Explanation     ✗
```

This allows the application to run on systems that cannot support a local language model.

---

# 30. AI Hardware Considerations

Local language models may require significant RAM and compute resources.

Therefore:

* Smaller models should be preferred for low-resource machines.
* The AI module should be optional.
* AI requests should be asynchronous where appropriate.
* The application should expose AI availability in system status.

---

# 31. Database Backup

The initial database is:

```text
netwatch.db
```

A backup may be created by:

```text
Stop or safely quiesce database writes
        |
        v
Copy Database
        |
        v
Backup Directory
```

Future versions may implement automated backups.

Backups should be protected because they can contain network and security information.

---

# 32. Logs

Application logs should be stored separately from application source files.

Example:

```text
backend/
└── logs/
    ├── application.log
    ├── detection.log
    └── error.log
```

Log retention should be configurable.

Logs should avoid unnecessarily storing sensitive packet payloads or credentials.

---

# 33. Data Retention

The initial recommended retention strategy:

```text
Raw Packet Metadata       30 days
Connections               90 days
Traffic Statistics        180 days
Protocol Statistics       180 days
Alerts                    Long-term
Alert Evidence            Long-term
AI Insights               180 days
Notifications             90 days
```

These values should remain configurable.

---

# 34. Production-Like Build

After development is stable, the frontend can be built.

Example:

```bash
npm run build
```

This creates a production build.

The backend can then serve the API while the frontend can be hosted by an appropriate static file server.

The exact production deployment method is outside the initial local deployment scope.

---

# 35. Docker Deployment

Docker is optional for the initial release.

Potential structure:

```text
docker/
├── backend/
│   └── Dockerfile
├── frontend/
│   └── Dockerfile
└── docker-compose.yml
```

Possible services:

```text
frontend
backend
database
```

For the initial SQLite deployment, a separate database container is not required.

---

# 36. Packet Capture and Docker

Packet capture inside Docker can require:

* Host networking
* Additional Linux capabilities
* Access to network interfaces
* Appropriate security permissions

Therefore, Docker should not be considered the easiest first deployment method for packet capture.

Recommended order:

```text
Local Native Deployment
       ↓
Stable Application
       ↓
Docker
       ↓
Optional Distributed Deployment
```

---

# 37. Development Startup Checklist

```text
[ ] Python environment activated
[ ] Backend dependencies installed
[ ] Frontend dependencies installed
[ ] Environment variables configured
[ ] SQLite database initialized
[ ] Backend running
[ ] Frontend running
[ ] Network interface available
[ ] Packet capture permissions available
[ ] WebSocket connection working
```

---

# 38. Application Verification

After startup, verify the following.

## Backend

```text
FastAPI:
Running

Database:
Connected

API:
Healthy
```

## Frontend

```text
React:
Running

Dashboard:
Accessible

API:
Connected

WebSocket:
Connected
```

## Capture

```text
Interface:
Available

Capture:
Stopped initially

Start Capture:
Working
```

---

# 39. Functional Verification

The first deployment should verify:

```text
Start Capture
      ↓
Packet Count Increases
      ↓
Traffic Chart Updates
      ↓
Device Appears
      ↓
Protocol Statistics Update
      ↓
Detection Engine Processes Traffic
      ↓
Alert Appears When Test Activity Triggers Detection
```

---

# 40. Troubleshooting

## Backend Does Not Start

Check:

```bash
python --version
pip list
```

Verify that dependencies are installed.

---

## Frontend Does Not Start

Check:

```bash
node --version
npm --version
```

Then reinstall dependencies:

```bash
npm install
```

---

## API Cannot Be Reached

Verify that FastAPI is running:

```text
http://127.0.0.1:8000/docs
```

Check the frontend API base URL.

---

## WebSocket Does Not Connect

Verify:

```text
FastAPI WebSocket endpoint
Frontend WebSocket URL
Port
Firewall
```

---

## No Packets Captured

Check:

* Correct network interface selected.
* Packet capture driver installed.
* Required permissions available.
* Interface is active.
* Capture filter is not too restrictive.

---

## No Alerts Generated

Check:

* Detection rule is enabled.
* Required traffic is actually being observed.
* Feature window is populated.
* Threshold is appropriate.
* Detection logs contain no errors.

---

# 41. Security Considerations

The deployment should follow these rules:

1. Monitor only authorized networks.
2. Do not expose the local monitoring API publicly without authentication and appropriate security controls.
3. Do not commit `.env` files containing secrets.
4. Protect database backups.
5. Avoid unnecessary packet payload storage.
6. Restrict access to captured traffic.
7. Use HTTPS when deploying beyond a trusted local development environment.
8. Do not enable automated blocking capabilities unless explicitly implemented, tested, and authorized.

---

# 42. Zero-Cost Deployment Model

The complete initial system can run locally:

```text
Local Computer
│
├── React
├── FastAPI
├── SQLite
├── Scapy
├── Scikit-learn
└── Optional Local AI
```

No paid services are required for the core system.

Potential optional external services must not become required dependencies for the base application.

---

# 43. Deployment Roadmap

## Phase 1

Local development:

```text
React
+
FastAPI
+
SQLite
+
Scapy
```

## Phase 2

Functional local deployment:

```text
Real Packet Capture
+
Detection
+
WebSocket
+
Reports
```

## Phase 3

AI-enabled local deployment:

```text
ML
+
Local LLM
```

## Phase 4

Containerized deployment:

```text
Docker
+
Docker Compose
```

## Phase 5

Future distributed architecture:

```text
Multiple Sensors
       ↓
Central Backend
       ↓
Central Database
       ↓
Dashboard
```

---

# 44. Deployment Principles

NetWatch AI deployment follows these principles:

1. Local-first.
2. Zero-cost for core functionality.
3. Minimal infrastructure.
4. Secure configuration.
5. Optional AI.
6. Controlled packet-capture permissions.
7. Reproducible development environment.
8. Configurable data retention.
9. Clear separation between development and production-like deployment.
10. Docker and distributed deployment are future enhancements rather than initial requirements.

---

# 45. Conclusion

NetWatch AI is designed to run initially as a local cybersecurity monitoring platform using open-source technologies.

The basic runtime consists of:

```text
React Frontend
       |
       v
FastAPI Backend
       |
       +---- SQLite
       |
       +---- Packet Capture
       |
       +---- Detection Engine
       |
       +---- ML Engine
       |
       +---- Optional Local AI
```

The initial deployment requires no paid cloud infrastructure or commercial security services.

The recommended development process is to first stabilize the native local deployment, then introduce optional Docker and distributed deployment capabilities after the core monitoring and detection functionality has been validated.


