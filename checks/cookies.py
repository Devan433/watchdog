from core.models import Finding
from core.http_client import fetch_page, SafeRequestException


def check_cookies(url: str) -> list[Finding]:
    findings = []

    try:
        response = fetch_page(url, allow_redirects=True)
    except SafeRequestException as e:
        return [Finding(
            check_name="Cookies Scan",
            category="cookies",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None,
        )]

    cookies = response.cookies

    if not cookies:
        findings.append(Finding(
            check_name="Cookies",
            category="cookies",
            passed=True,
            severity="info",
            detail="No cookies set by this page",
            fix="No action needed",
            evidence=None,
        ))
        return findings

    for cookie in cookies:
        cookie_findings = check_single_cookie(cookie)
        findings.extend(cookie_findings)

    return findings


def check_single_cookie(cookie) -> list[Finding]:
    findings = []
    name = cookie.name

    name_lower = name.lower()
    is_csrf_cookie = "csrf" in name_lower or "xsrf" in name_lower
    is_session_cookie = (
        any(x in name_lower for x in ["session", "auth", "token", "jwt", "sid"])
        and not is_csrf_cookie
    )

    httponly = cookie.has_nonstandard_attr("HttpOnly") or bool(cookie._rest.get("HttpOnly"))
    if not httponly:
        if is_session_cookie:
            severity = "high"
            confidence = "high"
            detail = f"Cookie '{name}' is missing HttpOnly flag. Since this looks like a session/auth cookie, XSS attacks could steal it."
        else:
            severity = "info"
            confidence = "low"
            detail = f"Cookie '{name}' is missing HttpOnly flag. JavaScript can read it, but it does not appear to be a session cookie (likely tracking/analytics)."

        findings.append(Finding(
            check_name=f"Cookie: {name} — HttpOnly",
            category="cookies",
            passed=False,
            severity=severity,
            detail=detail,
            fix=f"If '{name}' is a session cookie, set HttpOnly. If it is an analytics/tracking cookie, it is safe to ignore.",
            evidence=f"Cookie: {name}",
            confidence=confidence,
            is_third_party=False,
        ))
    else:
        findings.append(Finding(
            check_name=f"Cookie: {name} — HttpOnly",
            category="cookies",
            passed=True,
            severity="info",
            detail=f"Cookie '{name}' has HttpOnly flag set",
            fix="No action needed",
            evidence=f"Cookie: {name}",
            confidence="high",
            is_third_party=False,
        ))

    if not cookie.secure:
        findings.append(Finding(
            check_name=f"Cookie: {name} — Secure",
            category="cookies",
            passed=False,
            severity="medium" if is_session_cookie else "low",
            detail=f"Cookie '{name}' is missing Secure flag. Cookie can be transmitted over HTTP.",
            fix=f"Set Secure flag on '{name}'.",
            evidence=f"Cookie: {name}",
            confidence="high",
            is_third_party=False,
        ))
    else:
        findings.append(Finding(
            check_name=f"Cookie: {name} — Secure",
            category="cookies",
            passed=True,
            severity="info",
            detail=f"Cookie '{name}' has Secure flag set",
            fix="No action needed",
            evidence=f"Cookie: {name}",
            confidence="high",
            is_third_party=False,
        ))

    samesite = cookie._rest.get("SameSite") or cookie.has_nonstandard_attr("SameSite")

    if not samesite:
        findings.append(Finding(
            check_name=f"Cookie: {name} — SameSite",
            category="cookies",
            passed=False,
            severity="low",
            detail=f"Cookie '{name}' is missing SameSite attribute.",
            fix=f"Set SameSite on '{name}' if it is a sensitive cookie.",
            evidence=f"Cookie: {name}",
            confidence="high",
            is_third_party=False,
        ))
    else:
        findings.append(Finding(
            check_name=f"Cookie: {name} — SameSite",
            category="cookies",
            passed=True,
            severity="info",
            detail=f"Cookie '{name}' has SameSite attribute set",
            fix="No action needed",
            evidence=f"Cookie: {name}",
            confidence="high",
            is_third_party=False,
        ))

    return findings
