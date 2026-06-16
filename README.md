# Watchdog (Security Linter)

**Watchdog** is a pre-deployment security linting tool designed for developers. It allows engineering teams to scan a web application URL prior to launching, providing a comprehensive report on common security misconfigurations, exposed secrets, and deployment risks. 

Unlike heavy penetration testing tools, Watchdog focuses on immediate, actionable fixes that developers can implement quickly to secure their web applications.

## Key Features

- **Security Headers Validation:** Checks for the presence of critical headers like `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), and `X-Frame-Options`.
- **SSL/TLS Checks:** Ensures HTTPS enforcement and monitors SSL certificate validity and expiration dates.
- **CORS Policy Assessment:** Detects overly permissive `Access-Control-Allow-Origin` wildcards, credential misconfigurations, and origin reflection vulnerabilities.
- **Cookie Security:** Verifies that session and authentication cookies properly utilize `HttpOnly`, `Secure`, and `SameSite` flags.
- **Sensitive Endpoint Probing:** Detects publicly exposed critical files and directories such as `/.env`, `/.git/config`, and database backups.
- **Secret Leak Detection:** Scans the main HTML document and linked JavaScript bundles for accidentally committed API keys (e.g., OpenAI, Stripe, AWS, GitHub).
- **Authentication Checks:** Identifies unauthenticated admin panels, unprotected JSON API endpoints, and forms vulnerable to default credentials.

## Technology Stack

- **Backend:** Python 3, Flask, `requests`, `beautifulsoup4`
- **Frontend:** Vanilla HTML, CSS, JavaScript (Zero external UI frameworks, customized clean design system)
- **Architecture:** Concurrent scanning using Python's `ThreadPoolExecutor` for rapid results.

## How It Works

1. The user inputs the target URL into the clean, minimalist dashboard.
2. The backend concurrently runs a suite of security probes against the target.
3. A security score (0-100) and grade (A-F) are calculated based on severity weightings.
4. The dashboard populates a prioritized checklist of issues, explaining *why* they matter and *how* to fix them (e.g., specific header configurations or code snippets).

## Local Development

### Prerequisites
- Python 3.10+
- `pip`

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Devan433/watchdog.git
   cd watchdog
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the Flask development server:
   ```bash
   python app.py
   ```

4. Open your browser and navigate to `http://127.0.0.1:5000`.
