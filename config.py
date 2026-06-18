# ── Request settings ──────────────────────────────────────────
TIMEOUT = 10  # read timeout in seconds
CONNECT_TIMEOUT = 3  # connect timeout in seconds
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max response size
USER_AGENT = "Watchdog-Security-Scanner/1.0"

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Per-check orchestrator timeouts (seconds)
CHECK_TIMEOUTS = {
    "headers":     20,
    "ssl":         20,
    "cors":        20,
    "cookies":     20,
    "endpoints":   60,
    "secret_leak": 45,
    "auth":        60,
}

# ── Endpoints to probe (file/config exposure only; auth routes handled separately) ──
SENSITIVE_ENDPOINTS = [
    "/.env",
    "/.git/config",
    "/api/keys",
    "/phpinfo.php",
    "/config.php",
    "/backup.sql",
    "/wp-admin",
]

# ── Secret leak patterns ──────────────────────────────────────
SECRET_PATTERNS = {
    "openai_api_key":    r"sk-[a-zA-Z0-9]{32,}",
    "stripe_secret":     r"sk_live_[a-zA-Z0-9]{24,}",
    "stripe_public":     r"pk_live_[a-zA-Z0-9]{24,}",
    "supabase_key":      r"(?i)supabase[a-z_.-]{0,30}['\"]?(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
    "aws_access_key":    r"AKIA[0-9A-Z]{16}",
    "aws_secret":        r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "github_token":      r"ghp_[a-zA-Z0-9]{36}",
    "google_api_key":    r"AIza[0-9A-Za-z\-_]{35}",
}

THIRD_PARTY_DOMAINS = [
    "googleapis.com",
    "gstatic.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "googletagmanager.com",
    "google-analytics.com",
    "facebook.net",
    "stripe.com",
    "paypal.com",
]

# ── Security headers expected ─────────────────────────────────
EXPECTED_HEADERS = {
    "content-security-policy": {
        "check_name": "Content-Security-Policy",
        "severity": "medium",
        "detail": "CSP header is missing. Browsers won't know which sources are trusted.",
        "fix": "Add 'Content-Security-Policy: default-src \\'self\\'' to your server headers. In Express: app.use(helmet()). In Flask: use flask-talisman.",
    },
    "strict-transport-security": {
        "check_name": "Strict-Transport-Security (HSTS)",
        "severity": "medium",
        "detail": "HSTS header is missing. Browsers may load the site over HTTP.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your server headers.",
    },
    "x-frame-options": {
        "check_name": "X-Frame-Options",
        "severity": "low",
        "detail": "X-Frame-Options is missing. Site can be embedded in an iframe — clickjacking risk.",
        "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to your server headers.",
    },
    "x-content-type-options": {
        "check_name": "X-Content-Type-Options",
        "severity": "low",
        "detail": "X-Content-Type-Options is missing. Browser may MIME-sniff responses.",
        "fix": "Add 'X-Content-Type-Options: nosniff' to your server headers.",
    },
    "referrer-policy": {
        "check_name": "Referrer-Policy",
        "severity": "low",
        "detail": "Referrer-Policy is missing. Full URL may leak to third parties.",
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to your server headers.",
    },
    "permissions-policy": {
        "check_name": "Permissions-Policy",
        "severity": "low",
        "detail": "Permissions-Policy is missing. Browser features like camera/mic are unrestricted.",
        "fix": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()' to your server headers.",
    },
}

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
