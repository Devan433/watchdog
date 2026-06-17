import requests
from core.models import Finding
from config import TIMEOUT, HEADERS, EXPECTED_HEADERS
from core.http_client import safe_request, SafeRequestException

def check_headers(url: str) -> list[Finding]:
    findings = []

    try:
        response = safe_request(
            'GET',
            url,
            headers=HEADERS,
            allow_redirects=True
        )
    except SafeRequestException as e:
        return [Finding(
            check_name="Headers Scan",
            category="headers",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None
        )]

    # normalise to lowercase so "X-Frame-Options" and "x-frame-options" both match
    response_headers = {k.lower(): v for k, v in response.headers.items()}

    # ── Check each expected header ─────────────────────────────
    header_checks = {
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

    csp_header = response_headers.get("content-security-policy", "").lower()

    for header_key, meta in header_checks.items():
        if header_key not in response_headers:
            severity = meta["severity"]
            confidence = "high"
            passed = False
            detail = meta["detail"]
            
            # Contextual check: Missing X-Frame-Options is mitigated by CSP frame-ancestors
            if header_key == "x-frame-options" and "frame-ancestors" in csp_header:
                passed = True
                severity = "info"
                detail = "X-Frame-Options is missing, but protection is provided by CSP frame-ancestors."
                confidence = "high"
                
            findings.append(Finding(
                check_name=meta["check_name"],
                category="headers",
                passed=passed,
                severity=severity,
                detail=detail,
                fix=meta["fix"],
                evidence=None,
                confidence=confidence,
                is_third_party=False
            ))
        else:
            findings.append(Finding(
                check_name=meta["check_name"],
                category="headers",
                passed=True,
                severity="info",
                detail=f"{meta['check_name']} is present",
                fix="No action needed",
                evidence=response_headers[header_key],
                confidence="high",
                is_third_party=False
            ))

    return findings