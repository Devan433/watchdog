import os

# ── Request settings ──────────────────────────────────────────
TIMEOUT = 10  # seconds per request
USER_AGENT = "Watchdog-Security-Scanner/1.0"

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ── Endpoints to probe ────────────────────────────────────────
SENSITIVE_ENDPOINTS = [
    "/.env",
    "/.git/config",
    "/admin",
    "/admin/login",
    "/api/users",
    "/api/keys",
    "/phpinfo.php",
    "/config.php",
    "/backup.sql",
    "/wp-admin",
    "/dashboard",
]

# ── Secret leak patterns ──────────────────────────────────────
SECRET_PATTERNS = {
    "openai_api_key":    r"sk-[a-zA-Z0-9]{32,}",
    "stripe_secret":     r"sk_live_[a-zA-Z0-9]{24,}",
    "stripe_public":     r"pk_live_[a-zA-Z0-9]{24,}",
    "supabase_key":      r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "aws_access_key":    r"AKIA[0-9A-Z]{16}",
    "aws_secret":        r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "github_token":      r"ghp_[a-zA-Z0-9]{36}",
    "google_api_key":    r"AIza[0-9A-Za-z\-_]{35}",
}

# ── Security headers expected ─────────────────────────────────
EXPECTED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# ── Scoring thresholds ────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "critical": 30,
    "high":     15,
    "medium":   7,
    "low":      3,
    "info":     0,
}

GRADE_THRESHOLDS = {
    "A": 90,
    "B": 75,
    "C": 60,
    "D": 45,
}
# anything below D threshold = F