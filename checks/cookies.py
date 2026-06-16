import requests
from core.models import Finding
from config import TIMEOUT, HEADERS

def check_cookies(url: str) -> list[Finding]:
    findings = []

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True
        )
    except requests.exceptions.ConnectionError:
        return [Finding(
            check_name="Cookies Scan",
            category="cookies",
            passed=False,
            severity="critical",
            detail=f"Could not connect to {url}",
            fix="Check the URL is correct and the site is live",
            evidence=None
        )]
    except requests.exceptions.Timeout:
        return [Finding(
            check_name="Cookies Scan",
            category="cookies",
            passed=False,
            severity="critical",
            detail=f"Connection timed out after {TIMEOUT} seconds",
            fix="Site is too slow or blocking requests",
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
    if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
        findings.append(Finding(
            check_name=f"Cookie: {name} — HttpOnly",
            category="cookies",
            passed=False,
            severity="high",
            detail=f"Cookie '{name}' is missing HttpOnly flag. JavaScript can read this cookie — XSS attacks can steal it.",
            fix=f"Set HttpOnly flag on '{name}': Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict",
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
            severity="high",
            detail=f"Cookie '{name}' is missing Secure flag. Cookie can be transmitted over HTTP — vulnerable to interception.",
            fix=f"Set Secure flag on '{name}': Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict",
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
            severity="medium",
            detail=f"Cookie '{name}' is missing SameSite attribute. Vulnerable to CSRF attacks.",
            fix=f"Set SameSite on '{name}': Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict",
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