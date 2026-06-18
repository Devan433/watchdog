# WatchDawg

WatchDawg is a highly concurrent, pre-deployment security linter for web applications. It provides developers with an automated, lightweight, and blazingly fast security assessment to catch common misconfigurations before code reaches production. 

**Live Demo:** [https://watchdog-97l8.onrender.com/](https://watchdog-97l8.onrender.com/)

Designed for CI/CD pipelines and local development, WatchDawg actively audits a target URL against a suite of security checks, assigning a weighted score and letter grade based on the severity of its findings.

## Core Capabilities

- **Concurrent Execution**: Executes 7 distinct security check modules in parallel using Python's `ThreadPoolExecutor`.
- **SSRF Hardening**: Safely fetches target URLs using a heavily protected HTTP client that enforces DNS pinning, prohibits private/link-local IP addresses (such as `169.254.169.254`), and enforces strict response size limits.
- **SPA False-Positive Mitigation**: Implements an intelligent baseline content detection system. Single Page Applications (SPAs) that blindly return `200 OK` for missing routes are successfully filtered out to reduce false-positive endpoint exposure alerts.
- **Actionable AI Feedback**: Every detected vulnerability returns detailed evidence alongside an AI-ready `fix_prompt` that developers can paste directly into coding assistants (e.g., Cursor, Copilot) for instant remediation code.
- **Dual Interfaces**: Access the tool via a modern web dashboard or integrate it securely into CI/CD pipelines using the CLI.

---

## Security Modules

WatchDawg runs the following security audits concurrently:

### 1. Security Headers (`checks/headers.py`)
Audits the presence and configuration of essential HTTP headers.
- Evaluates `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Features fallback detection (e.g., recognizing `frame-ancestors` in CSP as a valid `X-Frame-Options` alternative).

### 2. SSL / TLS Verification (`checks/ssl_tls.py`)
Ensures transport layer security is strictly enforced.
- Flags insecure HTTP connections and validates proper redirects to HTTPS.
- Connects directly via socket to validate the target's OpenSSL certificate chain, failing upon expired or soon-to-expire certificates.

### 3. CORS Policy Probing (`checks/cors.py`)
Detects risky Cross-Origin Resource Sharing (CORS) rule sets.
- Probes the target with untrusted `Origin` headers (e.g., `https://evil.com`).
- Flags highly permissive rules, specifically the dangerous combination of `Access-Control-Allow-Origin: *` coupled with `Access-Control-Allow-Credentials: true`.

### 4. Cookie Flag Security (`checks/cookies.py`)
Examines all incoming `Set-Cookie` directives.
- Validates the presence of `HttpOnly`, `Secure`, and `SameSite` flags.
- Intelligently distinguishes between critical session tokens and standard tracking cookies, adjusting the penalty severity accordingly.

### 5. Sensitive Endpoints (`checks/endpoints.py`)
Probes the application for exposed configuration and backup files.
- Checks paths such as `/.env`, `/.git/config`, `/backup.sql`, and `/wp-admin`.
- Utilizes the SPA baseline detection logic to ignore synthetic 200 OK responses from catch-all routing.

### 6. Source Code Secret Leaks (`checks/secret_leak.py`)
Extracts and parses HTML and JavaScript bundles for accidentally committed API keys.
- Scans up to 5 linked JavaScript assets per target.
- Identifies AWS Access Keys, Stripe Secrets, OpenAI Tokens, GitHub Tokens, and more using robust regular expressions.
- Safely redacts discovered keys in the final report to prevent exposure in logs.

### 7. Authentication Hardening (`checks/auth_checks.py`)
Ensures critical administrative boundaries are properly protected.
- Scans known admin routes (e.g., `/admin/dashboard`) for unauthenticated access.
- Tests unauthenticated JSON API endpoints.
- Attempts basic default credential probing on recognized login forms.

---

## System Architecture

```mermaid
graph TD
  A([Client / Web UI]) -->|POST /scan| B[Flask App & Rate Limiter]
  B --> C{Orchestrator}
  
  subgraph Parallel Check Modules
    C -->|Thread 1| D[Headers Analysis]
    C -->|Thread 2| E[SSL/TLS Validation]
    C -->|Thread 3| F[CORS Policy Probing]
    C -->|Thread 4| G[Cookie Security]
    C -->|Thread 5| H[Sensitive Endpoints]
    C -->|Thread 6| I[Secret Leak Regex]
    C -->|Thread 7| J[Auth & Default Creds]
  end
  
  subgraph HTTP & Security Layer
    D & E & F & G & H & I & J --> K[Safe HTTP Client]
    K --> L((Per-Scan Page Cache))
    K --> M[DNS Pinning & SSRF Blocking]
  end
  
  K --> N[Target URL]
  D & E & F & G & H & I & J --> O[Finding Aggregator]
  O --> P[Scoring Engine]
  P --> Q([JSON Response / Dashboard])
```

---

## Scoring System

WatchDawg utilizes a deterministic grading algorithm. The scan begins at 100 points, deducting penalties based on the severity of failed checks.

- **Critical (-30 Points):** Severe vulnerabilities like exposed `.env` files or expired TLS certificates.
- **High (-15 Points):** Major risks like missing `HttpOnly` on session cookies.
- **Medium (-7 Points):** Moderate risks like permissive CORS.
- **Low (-3 Points):** Minor missing configurations like `Referrer-Policy`.
- **Info (0 Points):** Informational flags (e.g., 403 Forbidden on an admin route).

**Note:** To prevent minor issues from unjustly skewing the final grade, the cumulative penalty for "Low" severity findings is strictly capped at **15 points**.

---

## Installation & Setup

Ensure you have **Python 3.10+** installed.

```bash
# 1. Clone the repository
git clone https://github.com/Devan433/watchdog.git
cd watchdog

# 2. Initialize a Virtual Environment
python -m venv venv

# Activate Environment
source venv/bin/activate      # macOS / Linux
venv\Scripts\activate         # Windows

# 3. Install Required Dependencies
pip install -r requirements.txt
```

---

## Usage

### Web Dashboard

WatchDawg ships natively with the Waitress WSGI production server.

```bash
python app.py
```
*Access the interactive dashboard locally at `http://127.0.0.1:5000`.*

### Interpreting Results & AI Fix Prompts

Once a scan completes on the dashboard, you will be presented with a breakdown of vulnerabilities. WatchDawg isn't just about finding problems; it actively helps you fix them:

1. **Expand the Finding:** Click on any flagged issue to read the human-readable explanation and view the exact evidence (e.g., the exact header that was missing).
2. **Copy AI Fix Prompt:** Every finding includes a dynamically generated prompt. Click the "Copy AI Fix Prompt" button, then paste it directly into ChatGPT, Claude, or your IDE assistant (like Cursor or Copilot) to get immediate code fixes tailored to your stack!
3. **Deployment Checklist:** Use the quick sidebar to ensure your fundamental checkboxes (HTTPS, CSP, Cookies, Secrets) are green before you launch.

---

## Configuration

Core behaviors, timeouts, and scoring thresholds can be modified directly within `config.py`.

- **Timeouts**: Configurable globally and on a per-module basis (e.g., fast operations have a 20s hard limit, intensive probing allows up to 60s).
- **Secret Patterns**: Expandable regular expression dictionary for new token extraction.
- **Rate Limiting**: Globally set to 5 scans per minute per IP via `flask-limiter`. Multi-node deployments can synchronize state by exporting a `REDIS_URL` environment variable.
- **Target Endpoints**: Expand the list of sensitive files WatchDawg probes for inside `SENSITIVE_ENDPOINTS`.

---

## Testing

WatchDawg is supported by an extensive testing suite covering over 330 unit and integration tests. The suite leverages `pytest` and HTTP mocking via `responses` to validate the scoring engine, SSRF protections, and module-specific edge cases.

```bash
# Execute the full test suite
python -m pytest tests/ -v

# Run targeted module checks
python -m pytest tests/test_cors.py -v
```
