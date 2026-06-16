import requests
from core.models import Finding
from config import TIMEOUT, HEADERS
from core.http_client import safe_request, SafeRequestException

def check_cookies(url: str) -> list[Finding]:
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
            check_name="Cookies Scan",
            category="cookies",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None
        )]

    cookies = response.cookies

    # ── No cookies at all ─────────────────────────────────────
    if not cookies:
        findings.append(Finding(
            check_name="Cookies",
            category="cookies",
            passed=True,
            severity="info",
            detail="No cookies set by this page",
            fix="No action needed",
            evidence=None
        ))
        return findings

    # ── Check each cookie ─────────────────────────────────────
    for cookie in cookies:
        cookie_findings = check_single_cookie(cookie)
        findings.extend(cookie_findings)

    return findings


def check_single_cookie(cookie) -> list[Finding]:
    findings = []
    name = cookie.name

    # ── HttpOnly ──────────────────────────────────────────────
    name_lower = name.lower()
    is_session_cookie = any(x in name_lower for x in ['session', 'auth', 'token', 'jwt', 'sid'])

    if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
        severity = "high" if is_session_cookie else "low"
        detail = f"Cookie '{name}' is missing HttpOnly flag. JavaScript can read it."
        if is_session_cookie:
            detail += " Since this looks like a session/auth cookie, XSS attacks could steal it."
            
        findings.append(Finding(
            check_name=f"Cookie: {name} — HttpOnly",
            category="cookies",
            passed=False,
            severity=severity,
            detail=detail,
            fix=f"If '{name}' is a session cookie, set HttpOnly. If it is an analytics/tracking cookie, it is safe to ignore.",
            evidence=f"Cookie: {name}"
        ))
    else:
        findings.append(Finding(
            check_name=f"Cookie: {name} — HttpOnly",
            category="cookies",
            passed=True,
            severity="info",
            detail=f"Cookie '{name}' has HttpOnly flag set",
            fix="No action needed",
            evidence=f"Cookie: {name}"
        ))

    # ── Secure ────────────────────────────────────────────────
    if not cookie.secure:
        findings.append(Finding(
            check_name=f"Cookie: {name} — Secure",
            category="cookies",
            passed=False,
            severity="medium",
            detail=f"Cookie '{name}' is missing Secure flag. Cookie can be transmitted over HTTP.",
            fix=f"Set Secure flag on '{name}'.",
            evidence=f"Cookie: {name}"
        ))
    else:
        findings.append(Finding(
            check_name=f"Cookie: {name} — Secure",
            category="cookies",
            passed=True,
            severity="info",
            detail=f"Cookie '{name}' has Secure flag set",
            fix="No action needed",
            evidence=f"Cookie: {name}"
        ))

    # ── SameSite ──────────────────────────────────────────────
    samesite = cookie._rest.get("SameSite") or cookie.has_nonstandard_attr("SameSite")

    if not samesite:
        findings.append(Finding(
            check_name=f"Cookie: {name} — SameSite",
            category="cookies",
            passed=False,
            severity="low",
            detail=f"Cookie '{name}' is missing SameSite attribute.",
            fix=f"Set SameSite on '{name}' if it is a sensitive cookie.",
            evidence=f"Cookie: {name}"
        ))
    else:
        findings.append(Finding(
            check_name=f"Cookie: {name} — SameSite",
            category="cookies",
            passed=True,
            severity="info",
            detail=f"Cookie '{name}' has SameSite attribute set",
            fix="No action needed",
            evidence=f"Cookie: {name}"
        ))

    return findings