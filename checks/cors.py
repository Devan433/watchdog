from core.models import Finding
from config import HEADERS
from core.http_client import fetch_page, safe_request, SafeRequestException

EVIL_ORIGIN = "https://evil.com"


def check_cors(url: str) -> list[Finding]:
    findings = []

    try:
        get_response = fetch_page(url, allow_redirects=True, headers={**HEADERS, "Origin": EVIL_ORIGIN})
    except SafeRequestException as e:
        return [Finding(
            check_name="CORS Policy",
            category="cors",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None,
        )]

    findings.extend(_analyze_cors_headers(get_response.headers, "GET"))

    try:
        options_response = safe_request(
            "OPTIONS",
            url,
            headers={
                **HEADERS,
                "Origin": EVIL_ORIGIN,
                "Access-Control-Request-Method": "POST",
            },
            allow_redirects=True,
        )
        options_findings = _analyze_cors_headers(options_response.headers, "OPTIONS")
        existing_names = {f.check_name for f in findings}
        for finding in options_findings:
            if finding.check_name not in existing_names and not finding.passed:
                findings.append(finding)
    except SafeRequestException:
        pass

    if not findings:
        findings.append(Finding(
            check_name="CORS Policy",
            category="cors",
            passed=True,
            severity="info",
            detail="No CORS headers found. This is fine if this is not an API.",
            fix="No action needed unless this is an API intended for cross-origin access.",
            evidence=None,
            confidence="high",
            is_third_party=False,
        ))

    return findings


def _analyze_cors_headers(headers: dict, method: str) -> list[Finding]:
    findings = []
    response_headers = {k.lower(): v for k, v in headers.items()}

    acao = response_headers.get("access-control-allow-origin")
    acac = response_headers.get("access-control-allow-credentials")

    if acao == "*" and acac and acac.lower() == "true":
        findings.append(Finding(
            check_name="CORS Wildcard With Credentials",
            category="cors",
            passed=False,
            severity="critical",
            detail=f"Server allows wildcard origin AND credentials on {method}. Browsers block this but it signals a deeply misconfigured CORS policy.",
            fix="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use explicit origins.",
            evidence=f"ACAO: {acao} | ACAC: {acac}",
            confidence="high",
            is_third_party=False,
        ))
    elif acao == "*":
        findings.append(Finding(
            check_name="CORS Wildcard Origin",
            category="cors",
            passed=False,
            severity="medium",
            detail=f"Server accepts requests from any origin on {method} (Access-Control-Allow-Origin: *). This may be intentional for public APIs.",
            fix="Replace '*' with your specific frontend domain: 'Access-Control-Allow-Origin: https://yourdomain.com'",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            confidence="low",
            is_third_party=False,
        ))
    elif acao == EVIL_ORIGIN:
        findings.append(Finding(
            check_name="CORS Origin Reflection",
            category="cors",
            passed=False,
            severity="high",
            detail=f"Server reflects any Origin header back without validation on {method}. Any website can make credentialed requests to your API.",
            fix="Maintain an explicit allowlist of trusted origins and only reflect those. Never reflect arbitrary Origin headers.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            confidence="medium",
            is_third_party=False,
        ))
    elif acao is not None:
        findings.append(Finding(
            check_name="CORS Policy",
            category="cors",
            passed=True,
            severity="info",
            detail=f"CORS is restricted to a specific origin on {method}: {acao}",
            fix="No action needed",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            confidence="high",
            is_third_party=False,
        ))

    return findings
