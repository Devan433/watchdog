# WatchDawg — Pre-Deployment Security Linter

**WatchDawg** is a developer-focused security linting tool for web applications. Enter a URL, run a scan, and get an actionable report covering headers, TLS, CORS, cookies, exposed files, leaked secrets, and basic authentication issues — with a score, grade, and fix instructions.

It is designed to answer one question before you ship:

> *"Are there obvious security mistakes on this site that I can fix in minutes?"*

WatchDawg is **not** a penetration testing framework. It is a fast, lightweight linter — closer to ESLint for security than to OWASP ZAP.

---

## Table of Contents

1. [What WatchDawg Does](#what-WatchDawg-does)
2. [What WatchDawg Does NOT Do](#what-WatchDawg-does-not-do)
3. [Key Features](#key-features)
4. [Technology Stack](#technology-stack)
5. [Project Structure](#project-structure)
6. [Architecture Overview](#architecture-overview)
7. [How a Scan Works (Step by Step)](#how-a-scan-works-step-by-step)
8. [Security Checks (Detailed)](#security-checks-detailed)
9. [Scoring & Grading System](#scoring--grading-system)
10. [Data Models](#data-models)
11. [API Reference](#api-reference)
12. [Web Dashboard](#web-dashboard)
13. [CLI Usage (CI/CD)](#cli-usage-cicd)
14. [Configuration Reference](#configuration-reference)
15. [Installation](#installation)
16. [Running WatchDawg](#running-WatchDawg)
17. [Testing](#testing)
18. [Deployment](#deployment)
19. [Scanner Security (Protecting WatchDawg Itself)](#scanner-security-protecting-WatchDawg-itself)
20. [Limitations & False Positives](#limitations--false-positives)
21. [Legal & Ethical Use](#legal--ethical-use)
22. [Troubleshooting](#troubleshooting)
23. [Extending WatchDawg](#extending-WatchDawg)

---

## What WatchDawg Does

WatchDawg performs **passive and light active checks** against a public URL:

| Category        | What it checks |
|-----------------|----------------|
| **Headers**     | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **SSL/TLS**     | HTTPS usage, HTTP→HTTPS redirect, certificate validity, expiry |
| **CORS**        | Wildcard origins, origin reflection, credentials + wildcard |
| **Cookies**     | HttpOnly, Secure, SameSite flags on session/tracking cookies |
| **Endpoints**   | Exposed sensitive files (`.env`, `.git/config`, backups, etc.) |
| **Secret Leak** | API keys in HTML/JS (OpenAI, Stripe, AWS, GitHub, Google, Supabase) |
| **Auth**        | Unprotected admin routes, open JSON APIs, default credentials |

Each issue includes:

- **Severity** — critical / high / medium / low / info
- **Detail** — what was found and why it matters
- **Fix** — concrete remediation steps (often with framework hints)
- **Evidence** — redacted proof (header value, status code, etc.)
- **Confidence** — high / medium / low (helps triage false positives)
- **fix_prompt** — ready-to-paste prompt for AI coding assistants

---

## What WatchDawg Does NOT Do

Be clear with users and clients about scope:

- ❌ Full penetration testing or exploit chaining
- ❌ Deep crawling of entire sites
- ❌ SQL injection, XSS, or CSRF vulnerability testing
- ❌ Authenticated scanning (no login/session support)
- ❌ Infrastructure scanning (open ports, firewall rules)
- ❌ Guaranteed zero false positives

WatchDawg finds **common pre-launch mistakes**. A clean report does not mean the app is fully secure.

---

## Key Features

- **Concurrent scanning** — all 7 check modules run in parallel via `ThreadPoolExecutor`
- **Actionable output** — every finding includes a human-readable fix, not just a rule ID
- **AI-ready fix prompts** — copy a structured prompt into Cursor, Claude, etc.
- **False-positive awareness** — SPA baseline detection, CSP fallbacks, third-party script downgrades
- **Smart scoring** — weighted penalties with a cap on low-severity issues
- **Dual interface** — web dashboard + CLI for CI pipelines
- **SSRF-hardened HTTP client** — DNS pinning, private IP blocking, response size limits
- **Production-ready server** — Waitress WSGI, rate limiting, concurrency control
- **332 automated tests** — unit tests for checks, scorer, and HTTP safety

---

## Technology Stack

| Layer      | Technology |
|------------|------------|
| Backend    | Python 3.10+, Flask |
| HTTP       | `requests` with custom safe wrapper |
| HTML parse | `beautifulsoup4` |
| Server     | `waitress` (production WSGI) |
| Rate limit | `flask-limiter` |
| Frontend   | Vanilla HTML, CSS, JavaScript (no frameworks) |
| Testing    | `pytest`, `responses` |

---

## Project Structure

```
WatchDawg/
├── app.py                  # Flask app, routes, CLI entry point
├── config.py               # Timeouts, patterns, scoring weights, probe lists
├── requirements.txt        # Python dependencies
│
├── core/
│   ├── orchestrator.py     # Runs all checks concurrently, builds final result
│   ├── http_client.py      # SSRF-safe HTTP layer + page cache
│   ├── models.py           # Finding and ScanResult dataclasses
│   ├── scorer.py           # Score (0–100) and grade (A–F) calculation
│   └── formatter.py        # JSON API response formatting
│
├── checks/
│   ├── headers.py          # Security response headers
│   ├── ssl_tls.py          # HTTPS and certificate checks
│   ├── cors.py             # Cross-Origin Resource Sharing policy
│   ├── cookies.py          # Cookie flag analysis
│   ├── endpoints.py        # Sensitive file/path exposure
│   ├── secret_leak.py      # Regex scan for leaked API keys
│   └── auth_checks.py      # Admin/API auth + default credentials
│
├── templates/
│   └── index.html          # Web dashboard shell
│
├── static/
│   ├── style.css           # UI styling
│   └── script.js           # Scan UI, results rendering, copy fix prompt
│
└── tests/
    ├── conftest.py         # Resets cache/state between tests
    ├── test_scorer.py
    ├── test_headers.py
    ├── test_cors.py
    ├── test_cookies.py
    ├── test_endpoints.py
    ├── test_secret_leak.py
    ├── test_http_client.py
    └── test_massive.py     # 300 parametrized scoring tests
```

---

## Architecture Overview

```
┌─────────────┐     POST /scan      ┌──────────────┐
│  Web UI /   │ ──────────────────► │    app.py    │
│  CLI        │                     │  (Flask)     │
└─────────────┘                     └──────┬───────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │  orchestrator   │
                                  │  run_scan(url)  │
                                  └────────┬────────┘
                                           │
              ┌────────────────────────────┼────────────────────────────┐
              │                            │                            │
              ▼                            ▼                            ▼
     ┌────────────────┐          ┌────────────────┐          ┌────────────────┐
     │ check_headers  │          │  check_ssl     │   ...    │  check_auth    │
     │ check_cors     │          │  check_cookies │          │  check_secrets │
     │ check_endpoints│          │                │          │                │
     └───────┬────────┘          └───────┬────────┘          └───────┬────────┘
             │                           │                           │
             └───────────────────────────┼───────────────────────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │   http_client.py    │
                              │  safe_request()     │
                              │  fetch_page() cache │
                              │  DNS pinning / SSRF │
                              └─────────────────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │  scorer + formatter │
                              │  JSON response      │
                              └─────────────────────┘
```

### Design principles

1. **One function = one check module** — each file in `checks/` exports a single `check_*(url) -> list[Finding]` function.
2. **Uniform output** — every check returns the same `Finding` dataclass regardless of category.
3. **Parallel by default** — checks are independent and run concurrently; slow targets get per-check timeouts.
4. **Safe HTTP everywhere** — all outbound requests go through `safe_request()` or cached `fetch_page()`.
5. **Developer UX first** — fixes are written for humans (and AI assistants), not security auditors.

---

## How a Scan Works (Step by Step)

1. **Input validation** (`app.py`)
   - URL must be a string, max 2048 characters
   - Must match domain pattern (`http://` or `https://`)
   - `https://` is prepended if scheme is missing (CLI only; web requires explicit scheme)

2. **Cache cleared** (`orchestrator.py`)
   - Per-scan HTTP cache reset so results are isolated

3. **Seven checks launched in parallel**
   - Each runs in its own thread with an individual timeout (20–60 seconds)

4. **HTTP layer** (`http_client.py`)
   - Hostname resolved and validated against SSRF rules
   - DNS pinned to resolved IP at connection time (prevents rebinding)
   - Response body streamed with 5 MB hard cap
   - Redirects followed up to 10 hops, re-validated each hop

5. **Findings collected**
   - All `Finding` objects merged into one list
   - Timeouts/errors become info-level findings (don't crash the scan)

6. **Score calculated** (`scorer.py`)
   - Start at 100, subtract weighted penalties for failed findings
   - Low-severity penalties capped at 15 total
   - Grade assigned: A / B / C / D / F

7. **JSON formatted** (`formatter.py`)
   - Grouped by category, includes breakdown, summary, fix prompts

8. **UI or CLI renders results**

Typical scan time: **5–15 seconds** for a normal public website.

---

## Security Checks (Detailed)

### 1. Security Headers (`checks/headers.py`)

Fetches the main page (cached) and checks for six headers defined in `config.py → EXPECTED_HEADERS`:

| Header | Default severity if missing |
|--------|----------------------------|
| Content-Security-Policy | medium |
| Strict-Transport-Security | medium |
| X-Frame-Options | low |
| X-Content-Type-Options | low |
| Referrer-Policy | low |
| Permissions-Policy | low |

**Smart fallback:** If `X-Frame-Options` is missing but CSP contains `frame-ancestors`, the check passes (clickjacking is still mitigated).

**Fix hints include:** Express `helmet()`, Flask `flask-talisman`, raw Nginx/Apache config snippets.

---

### 2. SSL/TLS (`checks/ssl_tls.py`)

**For HTTP URLs:**
- Flags plaintext transport as **critical**
- Checks whether HTTP redirects to HTTPS

**For HTTPS URLs:**
- Validates certificate chain via OpenSSL
- Checks expiry:
  - Expired → **critical**
  - Expires within 30 days → **medium**
  - Valid → pass with days remaining

Connects to the resolved IP with correct SNI hostname for certificate validation.

---

### 3. CORS Policy (`checks/cors.py`)

Sends requests with a fake origin: `https://evil.com`

**GET request** on the base URL, plus **OPTIONS preflight** with:
```
Origin: https://evil.com
Access-Control-Request-Method: POST
```

| Condition | Severity |
|-----------|----------|
| `ACAO: *` + `ACAC: true` | critical |
| `ACAO: *` | medium (may be intentional for public APIs) |
| `ACAO` reflects evil origin | high |
| Specific allowed origin | pass |
| No CORS headers | pass (fine for non-API pages) |

---

### 4. Cookie Security (`checks/cookies.py`)

Analyzes all `Set-Cookie` headers from the main page response.

For each cookie, checks three flags:

| Flag | Session cookie missing it | Tracking cookie missing it |
|------|--------------------------|---------------------------|
| HttpOnly | high | info (low confidence) |
| Secure | medium | low |
| SameSite | low | low |

**Session detection:** Cookie name contains `session`, `auth`, `token`, `jwt`, or `sid` — excluding `csrf`/`xsrf` tokens.

---

### 5. Sensitive Endpoints (`checks/endpoints.py`)

Probes a fixed list of paths in **parallel** (6 workers):

```
/.env
/.git/config
/api/keys
/phpinfo.php
/config.php
/backup.sql
/wp-admin
```

**Detection logic:**
- HTTP 200 → potentially exposed
- HTTP 403 → info (path may exist but blocked — no score penalty)
- HTTP 404 → not reported

**False-positive mitigation (SPA apps):**
1. Requests a random non-existent path first to establish a baseline response length
2. If probed path returns 200 but content length is within 10% of baseline → ignored
3. If HTML contains "404" / "not found" → downgraded to info / low confidence
4. For `/.git/config`, content must contain `[core]` to be treated as a real git config

Admin/API route auth is handled separately by `auth_checks.py` to avoid duplicate findings.

---

### 6. Secret Leak Detection (`checks/secret_leak.py`)

Scans:
1. Main HTML page source
2. Up to **5 linked JavaScript files** (from `<script src="...">` tags)

**Patterns detected** (`config.py → SECRET_PATTERNS`):

| Secret type | Pattern hint |
|-------------|--------------|
| OpenAI API key | `sk-...` (32+ chars) |
| Stripe secret | `sk_live_...` |
| Stripe public | `pk_live_...` |
| Supabase JWT | `supabase` context + JWT format |
| AWS access key | `AKIA...` |
| AWS secret | `aws` + 40-char string |
| GitHub token | `ghp_...` |
| Google API key | `AIza...` |

**Safety measures:**
- Evidence is **redacted** (first 6 + last 4 chars only)
- Dummy strings filtered (`example`, `123456789`, `your_api_key`)
- Third-party CDN scripts downgraded to **info / low confidence**
- Public-by-design keys (Stripe publishable, Google API key) → **medium** not critical

---

### 7. Authentication Checks (`checks/auth_checks.py`)

Three sub-checks, all run in parallel:

**A. Unprotected admin routes** (GET, no cookies/auth):
```
/admin, /admin/dashboard, /admin/users, /dashboard, /manage, /panel
```
- HTTP 200 without auth → **high**
- HTTP 302 to login → pass

**B. Unauthenticated JSON APIs** (GET, no auth):
```
/api/users, /api/admin, /api/config, /api/settings, /api/v1/users, /api/v2/users
```
- HTTP 200 + `Content-Type: application/json` + non-empty body → **high**

**C. Default credentials** (POST to login pages):
```
/login, /admin/login, /wp-login.php
```
Tries combinations:
- `admin:admin`, `admin:password`, `admin:123456`

Sends both **JSON** and **form-urlencoded** POST bodies. Detects success via redirect away from login or JSON token response.

> ⚠️ This is best-effort only. Many real login forms use custom field names, CSRF tokens, or captchas and will not be tested accurately.

All auth checks use the same SPA baseline logic as endpoint probing.

---

## Scoring & Grading System

### Penalty weights

| Severity | Points deducted per failed finding |
|----------|-----------------------------------|
| critical | 30 |
| high | 15 |
| medium | 7 |
| low | 3 |
| info | 0 |

### Low-severity cap

Total penalty from **low** findings is capped at **15 points**. This prevents a site from getting grade F just because six optional headers are missing.

### Grade thresholds

| Grade | Minimum score |
|-------|--------------|
| A | 90 |
| B | 75 |
| C | 60 |
| D | 45 |
| F | below 45 |

### Examples

| Scenario | Score | Grade |
|----------|-------|-------|
| All checks pass | 100 | A |
| 1 critical issue | 70 | C |
| 10 low issues (30 pts raw) | 85 | B (capped at 15 low penalty) |
| 4 critical issues | 0 | F (clamped) |

### What affects the score

- Only findings where `passed: false` and severity is **not info** reduce the score
- Info-level failures (SPA false positives, third-party secrets, scan timeouts) appear in the report but **do not reduce the score**
- Passed findings contribute to the `passed` count in breakdown only

---

## Data Models

### `Finding`

```python
@dataclass
class Finding:
    check_name: str       # e.g. "Content-Security-Policy"
    category: str         # e.g. "headers", "ssl", "cors"
    passed: bool          # True = no issue
    severity: str         # critical | high | medium | low | info
    detail: str           # Human-readable description
    fix: str              # Remediation instructions
    evidence: str | None  # Redacted proof
    confidence: str       # high | medium | low
    is_third_party: bool  # True if from external CDN/script
```

### API response shape

```json
{
  "url": "https://example.com",
  "score": 74,
  "grade": "C",
  "summary": "2 medium, 4 low issues found — Grade C (74/100)",
  "breakdown": {
    "critical": 0,
    "high": 0,
    "medium": 2,
    "low": 4,
    "info": 0,
    "passed": 7
  },
  "categories": {
    "headers": [
      {
        "check_name": "...",
        "passed": false,
        "severity": "medium",
        "detail": "...",
        "fix": "...",
        "evidence": null,
        "confidence": "high",
        "is_third_party": false,
        "fix_prompt": "Fix this security issue..."
      }
    ],
    "ssl": [],
    "cors": [],
    "cookies": [],
    "endpoints": [],
    "secret_leak": [],
    "auth": []
  },
  "error": null
}
```

---

## API Reference

### `GET /`

Returns the web dashboard HTML.

---

### `POST /scan`

Run a security scan against a URL.

**Request:**
```http
POST /scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Success response:** `200 OK` — scan result JSON (see above)

**Error responses:**

| Status | Condition |
|--------|-----------|
| 400 | Missing URL, invalid format, URL too long |
| 429 | Rate limit exceeded (5 scans/minute per IP) |
| 502 | Scan failed internally |
| 503 | Server busy (max 10 concurrent scans) |

**Rate limits:**
- `/scan`: 5 requests per minute per IP
- Global: 50 per hour, 200 per day per IP

---

## Web Dashboard

Open `http://127.0.0.1:5000` after starting the server.

### UI sections

| Section | Description |
|---------|-------------|
| **Security Score** | 0–100 score, letter grade, deployment status badge |
| **Risk Overview** | Counts of critical / high / medium / low issues |
| **Prioritized Recommendations** | Top 5 unique fix strings, sorted by severity |
| **Detailed Findings** | Full issue cards with evidence and "Copy AI Fix Prompt" button |
| **Deployment Checklist** | Quick pass/fail for HTTPS, CSP, cookies, secrets |
| **Discovered Routes** | Exposed endpoint paths from probing |

### UI behavior

- Actionable findings exclude info-severity and low-confidence items from the main list
- Low-confidence findings shown separately with dashed border styling
- All user-facing text is HTML-escaped to prevent XSS from malicious scan targets
- Scan progress animation runs in parallel with the actual scan (cosmetic steps)

---

## CLI Usage (CI/CD)

WatchDawg includes a CLI for terminal use and CI pipelines.

### Basic scan

```bash
python app.py scan https://example.com
```

**Output:**
```
URL: https://example.com
Score: 74/100 (Grade C)
2 medium, 4 low issues found — Grade C (74/100)
  Critical: 0  High: 0  Medium: 2  Low: 4
```

### JSON output

```bash
python app.py scan https://example.com --json
```

### Fail CI if score is too low

```bash
python app.py scan https://example.com --fail-under 80
# Exit code 1 if score < 80
# Exit code 0 if score >= 80
# Exit code 2 on invalid URL or scan error
```

### Scan localhost (development only)

```bash
python app.py scan http://localhost:3000 --allow-localhost
```

> `--allow-localhost` is CLI-only. The web UI does not allow localhost scanning (prevents SSRF abuse on public deployments).

### GitHub Actions example

```yaml
- name: Security lint
  run: |
    pip install -r requirements.txt
    python app.py scan https://staging.myapp.com --fail-under 75
```

---

## Configuration Reference

All configuration lives in `config.py`.

### HTTP settings

| Variable | Default | Description |
|----------|---------|-------------|
| `TIMEOUT` | 10 | Read timeout (seconds) |
| `CONNECT_TIMEOUT` | 3 | Connect timeout (seconds) |
| `MAX_CONTENT_LENGTH` | 5 MB | Max response body size |
| `USER_AGENT` | `WatchDawg-Security-Scanner/1.0` | Outbound request User-Agent |

### Per-check timeouts (`CHECK_TIMEOUTS`)

| Check | Timeout |
|-------|---------|
| headers, ssl, cors, cookies | 20s |
| secret_leak | 45s |
| endpoints, auth | 60s |

### Environment variables

| Variable | Description |
|----------|-------------|
| `PORT` | Web server port (default: `5000`) |
| `REDIS_URL` | Redis URI for rate limit storage in multi-instance deployments (default: in-memory) |

### Customizing checks

- **Add secret patterns:** extend `SECRET_PATTERNS` in `config.py`
- **Add probed paths:** extend `SENSITIVE_ENDPOINTS` (files) or edit `auth_checks.py` (routes)
- **Adjust scoring:** edit `SEVERITY_WEIGHTS` and `GRADE_THRESHOLDS`
- **Add headers:** extend `EXPECTED_HEADERS` dict in `config.py`

---

## Installation

### Prerequisites

- Python **3.10 or newer**
- `pip`

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Devan433/WatchDawg.git
cd WatchDawg

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python -m pytest tests/ -q
# Expected: 332 passed
```

### Dependencies

```
Flask
requests
beautifulsoup4
waitress
flask-limiter
pytest          # for running tests
responses       # for HTTP mocking in tests
```

---

## Running WatchDawg

### Web server (production-style)

```bash
python app.py
# Starting Waitress production server on port 5000...
# Open http://127.0.0.1:5000
```

Uses **Waitress** WSGI server with 16 threads — not the Flask development server.

### Custom port

```bash
# Windows PowerShell
$env:PORT=8080; python app.py

# macOS / Linux
PORT=8080 python app.py
```

### CLI scan (no server needed)

```bash
python app.py scan https://yoursite.com
python app.py scan https://yoursite.com --json --fail-under 80
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Quick run
python -m pytest tests/ -q

# Run a specific module
python -m pytest tests/test_scorer.py -v
```

### Test coverage by area

| Test file | What it covers |
|-----------|---------------|
| `test_scorer.py` | Score calculation, grade boundaries, penalty cap |
| `test_massive.py` | 300 parametrized scoring combinations |
| `test_headers.py` | Header presence, CSP frame-ancestors fallback |
| `test_cors.py` | All CORS policy branches |
| `test_cookies.py` | Session vs tracking cookie severity |
| `test_endpoints.py` | SPA false positives, git config validation |
| `test_secret_leak.py` | Third-party downgrades, dummy key filtering |
| `test_http_client.py` | SSRF blocking, localhost CLI flag |

---

## Deployment

### Single instance (Render, Railway, VPS)

```bash
pip install -r requirements.txt
python app.py
```

Set `PORT` to match your platform's expected port.

### Multiple instances

Set `REDIS_URL` so rate limits are shared across instances:

```bash
REDIS_URL=redis://your-redis-host:6379 python app.py
```

Without Redis, each instance maintains its own in-memory rate limit counter.

### Reverse proxy

WatchDawg uses `ProxyFix` middleware and trusts one level of `X-Forwarded-For`, `X-Proto`, `X-Host`, and `X-Prefix` headers — compatible with Render, Nginx, and similar proxies.

### Recommended production checklist

- [ ] Deploy behind HTTPS (terminate TLS at proxy)
- [ ] Set `REDIS_URL` if running multiple workers/instances
- [ ] Add terms of use: users may only scan sites they own or have permission to test
- [ ] Monitor logs for abuse (rate limit 429 responses)
- [ ] Do not expose without rate limiting on public internet

---

## Scanner Security (Protecting WatchDawg Itself)

Because WatchDawg fetches user-supplied URLs, it implements several safeguards:

### SSRF protection (`core/http_client.py`)

- Resolves hostname before every request
- Blocks private, loopback, link-local, and multicast IPs
- Explicitly blocks cloud metadata IP `169.254.169.254`
- Re-validates on every redirect hop (max 10)
- **DNS pinning:** connects to the IP validated at check time (prevents DNS rebinding)

### Resource limits

- 5 MB max response body per request
- Connect timeout: 3 seconds
- Read timeout: 10 seconds per request
- Max 10 concurrent scans (semaphore)
- Rate limiting on `/scan` endpoint

### WatchDawg's own security headers

Every response from the WatchDawg app includes:
```
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy
Permissions-Policy
```

### Web UI XSS protection

Finding `detail`, `fix`, and `check_name` fields are HTML-escaped before rendering. Evidence fields are also escaped.

---

## Limitations & False Positives

| Scenario | Behavior |
|----------|----------|
| SPA apps (React, Vue, etc.) | May return 200 for all routes — baseline detection reduces false positives but is not perfect |
| Third-party CDN scripts | Secret-like strings downgraded to info / low confidence |
| Public API keys (Google, Stripe publishable) | Reported as medium, not critical |
| CORS on subpaths only | Only base URL + OPTIONS tested, not `/api` subpaths unless you scan that URL directly |
| Default credential check | Best-effort; most production login forms won't match |
| Secret scan | Regex-based; max 5 JS files; won't find secrets in lazy-loaded bundles |
| Auth check | Only unauthenticated GET/POST; no session support |
| 403 responses | Reported as info only — no score impact |

**Recommendation:** Treat WatchDawg as a **first pass**. Investigate critical/high findings immediately. Review low-confidence findings manually before acting.

---

## Legal & Ethical Use

WatchDawg sends HTTP requests to target URLs, including:
- GET requests to common admin and API paths
- POST requests with default credentials to login pages

**Only scan websites you own or have explicit written permission to test.**

Unauthorized scanning may violate:
- Computer fraud and abuse laws in your jurisdiction
- Your hosting provider's terms of service
- The target site's terms of use

If deploying WatchDawg as a public service, display a clear acceptable use policy.

---

## Troubleshooting

### Scan times out

```
"{check_name} check timed out after 60s"
```

**Cause:** Target is slow, blocking automated requests, or has many redirects.  
**Fix:** Retry. Scan a more specific URL (e.g. `https://app.example.com` instead of a heavy homepage).

---

### `503 Server is busy`

**Cause:** More than 10 scans running simultaneously.  
**Fix:** Wait a few seconds and retry.

---

### `429 Rate limit exceeded`

**Cause:** More than 5 scans per minute from your IP.  
**Fix:** Wait 60 seconds. In production, consider raising limits or requiring authentication.

---

### Score seems too harsh / too lenient

Edit `SEVERITY_WEIGHTS` and `GRADE_THRESHOLDS` in `config.py`.  
The low-severity cap (`MAX_LOW_PENALTY = 15` in `scorer.py`) prevents minor header gaps from dominating the score.

---

### Tests fail on `socket.gethostbyname`

Tests use the `responses` library to mock HTTP. If live DNS fails in your environment, ensure you have network access or mock DNS in tests.

---

### CLI can't scan localhost

Use the `--allow-localhost` flag:
```bash
python app.py scan http://localhost:3000 --allow-localhost
```

---

## Extending WatchDawg

### Add a new check

1. Create `checks/my_check.py`:
```python
from core.models import Finding

def check_my_thing(url: str) -> list[Finding]:
    findings = []
    # ... your logic ...
    findings.append(Finding(
        check_name="My Check",
        category="my_check",
        passed=True,
        severity="info",
        detail="All good",
        fix="No action needed",
    ))
    return findings
```

2. Register in `core/orchestrator.py`:
```python
from checks.my_check import check_my_thing

checks = {
    ...
    "my_check": check_my_thing,
}
```

3. Add timeout in `config.py → CHECK_TIMEOUTS`.

4. Add tests in `tests/test_my_check.py`.

### Use the HTTP layer in checks

```python
from core.http_client import safe_request, fetch_page, SafeRequestException

# Cached GET (shared across checks in same scan):
response = fetch_page(url, allow_redirects=True)

# One-off request:
response = safe_request("GET", f"{url}/some-path", allow_redirects=False)
```

---

## Quick Reference Card

```bash
# Install
pip install -r requirements.txt

# Web UI
python app.py

# Run tests
python -m pytest tests/ -q


## Summary

WatchDawg is a **pre-deployment security linter** that helps developers catch obvious security misconfigurations before they reach production. It combines seven parallel security checks, a weighted scoring system, actionable fix guidance, and both a web dashboard and CLI interface — hardened against SSRF abuse and designed to minimize false positives on modern web apps.

Use it early, use it often, and treat a passing grade as a strong starting point — not a final security audit.

---

**Repository:** https://github.com/Devan433/WatchDawg  
**Python:** 3.10+  
**License:** Add your license here
