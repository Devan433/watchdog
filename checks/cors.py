import requests
from core.models import Finding
from config import TIMEOUT, HEADERS
from core.http_client import safe_request, SafeRequestException

def check_cors(url: str) -> list[Finding]:
    findings = []

    evil_origin = "https://evil.com"

    try:
        response = safe_request(
            'GET',
            url,
            headers={**HEADERS, "Origin": evil_origin},
            allow_redirects=True
        )
    except SafeRequestException as e:
        return [Finding(
            check_name="CORS Policy",
            category="cors",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None
        )]

    response_headers = {k.lower(): v for k, v in response.headers.items()}

    acao = response_headers.get("access-control-allow-origin")
    acac = response_headers.get("access-control-allow-credentials")

    # ── Check 1: Wildcard + credentials (worst case) ────────────
    if acao == "*" and acac and acac.lower() == "true":
        findings.append(Finding(
            check_name="CORS Wildcard With Credentials",
            category="cors",
            passed=False,
            severity="critical",
            detail="Server allows wildcard origin AND credentials. Browsers block this but it signals a deeply misconfigured CORS policy.",
            fix="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use explicit origins.",
            evidence=f"ACAO: {acao} | ACAC: {acac}",
            confidence="high",
            is_third_party=False
        ))

    # ── Check 2: Wildcard CORS ────────────────────────────────
    elif acao == "*":
        findings.append(Finding(
            check_name="CORS Wildcard Origin",
            category="cors",
            passed=False,
            severity="medium",
            detail="Server accepts requests from any origin (Access-Control-Allow-Origin: *). Any website can read responses from your API. This may be intentional for public APIs.",
            fix="Replace '*' with your specific frontend domain: 'Access-Control-Allow-Origin: https://yourdomain.com'",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            confidence="low",
            is_third_party=False
        ))

    # ── Check 3: Reflecting evil origin ──────────────────────
    elif acao == evil_origin:
        findings.append(Finding(
            check_name="CORS Origin Reflection",
            category="cors",
            passed=False,
            severity="high",
            detail="Server reflects any Origin header back without validation. Any website can make credentialed requests to your API.",
            fix="Maintain an explicit allowlist of trusted origins and only reflect those. Never reflect arbitrary Origin headers.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            confidence="medium",
            is_third_party=False
        ))

    # ── Check 4: No CORS header (fine for non-APIs) ───────────
    elif acao is None:
        findings.append(Finding(
            check_name="CORS Policy",
            category="cors",
            passed=True,
            severity="info",
            detail="No CORS headers found. This is fine if this is not an API.",
            fix="No action needed unless this is an API intended for cross-origin access.",
            evidence=None,
            confidence="high",
            is_third_party=False
        ))

    # ── Check 5: Specific origin set correctly ────────────────
    else:
        findings.append(Finding(
            check_name="CORS Policy",
            category="cors",
            passed=True,
            severity="info",
            detail=f"CORS is restricted to a specific origin: {acao}",
            fix="No action needed",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            confidence="high",
            is_third_party=False
        ))

    return findings