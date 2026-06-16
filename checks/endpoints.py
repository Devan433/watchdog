import requests
from core.models import Finding
from config import TIMEOUT, HEADERS, SENSITIVE_ENDPOINTS
from core.http_client import safe_request, SafeRequestException

def check_endpoints(url: str) -> list[Finding]:
    findings = []
    base_url = url.rstrip("/")

    results = []

    # ── Probe all endpoints sequentially to prevent thread explosion ──
    for endpoint in SENSITIVE_ENDPOINTS:
        result = probe_endpoint(base_url, endpoint)
        if result:
            results.append(result)

    # ── No issues found ───────────────────────────────────────
    if not results:
        findings.append(Finding(
            check_name="Sensitive Endpoints",
            category="endpoints",
            passed=True,
            severity="info",
            detail="No sensitive endpoints found exposed",
            fix="No action needed",
            evidence=None
        ))
        return findings

    findings.extend(results)
    return findings


def probe_endpoint(base_url: str, endpoint: str) -> Finding | None:
    full_url = f"{base_url}{endpoint}"

    try:
        response = safe_request(
            'GET',
            full_url,
            headers=HEADERS,
            allow_redirects=False  # don't follow redirects — a 301 to login is not exposed
        )
    except SafeRequestException:
        return None
    except Exception:
        return None

    status = response.status_code

    # ── 200: definitely exposed ───────────────────────────────
    if status == 200:
        severity = get_severity(endpoint)
        return Finding(
            check_name=f"Exposed Endpoint: {endpoint}",
            category="endpoints",
            passed=False,
            severity=severity,
            detail=f"{endpoint} returned HTTP 200 — this path is publicly accessible",
            fix=get_fix(endpoint),
            evidence=f"GET {full_url} → {status}"
        )

    # ── 403: exists but blocked — still worth knowing ─────────
    if status == 403:
        return Finding(
            check_name=f"Restricted Endpoint: {endpoint}",
            category="endpoints",
            passed=False,
            severity="low",
            detail=f"{endpoint} returned HTTP 403 — path exists but access is blocked. Confirms the route is present.",
            fix="Consider returning 404 instead of 403 to avoid confirming the path exists",
            evidence=f"GET {full_url} → {status}"
        )

    return None


def get_severity(endpoint: str) -> str:
    critical_paths = ["/.env", "/.git/config", "/backup.sql", "/config.php"]
    high_paths = ["/api/users", "/api/keys", "/phpinfo.php"]

    if any(endpoint.startswith(p) for p in critical_paths):
        return "critical"
    if any(endpoint.startswith(p) for p in high_paths):
        return "high"
    return "medium"


def get_fix(endpoint: str) -> str:
    fixes = {
        "/.env": "Remove .env from your public directory immediately. Add .env to .gitignore. Rotate all exposed credentials.",
        "/.git/config": "Block access to .git directory in your server config. In Nginx: 'location ~ /\\.git { deny all; }'",
        "/backup.sql": "Remove database backups from public directories. Store them in private cloud storage.",
        "/phpinfo.php": "Delete phpinfo.php from production. It exposes server configuration details.",
        "/admin": "Restrict /admin to authenticated users only. Add IP allowlist if possible.",
        "/wp-admin": "Restrict wp-admin access. Use a security plugin like Wordfence.",
        "/api/users": "Add authentication to /api/users. It should never be publicly readable.",
        "/api/keys": "Remove or protect /api/keys immediately. Rotate any exposed keys.",
    }
    return fixes.get(endpoint, f"Restrict access to {endpoint} or remove it from production.")