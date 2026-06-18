from core.models import Finding
from config import EXPECTED_HEADERS
from core.http_client import fetch_page, SafeRequestException


def check_headers(url: str) -> list[Finding]:
    findings = []

    try:
        response = fetch_page(url, allow_redirects=True)
    except SafeRequestException as e:
        return [Finding(
            check_name="Headers Scan",
            category="headers",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None,
        )]

    response_headers = {k.lower(): v for k, v in response.headers.items()}
    csp_header = response_headers.get("content-security-policy", "").lower()

    for header_key, meta in EXPECTED_HEADERS.items():
        if header_key not in response_headers:
            severity = meta["severity"]
            confidence = "high"
            passed = False
            detail = meta["detail"]

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
                is_third_party=False,
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
                is_third_party=False,
            ))

    return findings
