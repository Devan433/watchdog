import concurrent.futures
from core.models import ScanResult, Finding
from core.scorer import calculate_score
from core.formatter import format_result
from checks.headers import check_headers
from checks.ssl_tls import check_ssl
from checks.cors import check_cors
from checks.cookies import check_cookies
from checks.endpoints import check_endpoints
from checks.secret_leak import check_secret_leak
from checks.auth_checks import check_auth
from config import TIMEOUT

def run_scan(url: str) -> dict:
    result = ScanResult(url=url)

    # ── Normalize URL ─────────────────────────────────────────
    if not url.startswith("http"):
        url = "https://" + url

    # ── Define all checks ─────────────────────────────────────
    checks = {
        "headers":     check_headers,
        "ssl":         check_ssl,
        "cors":        check_cors,
        "cookies":     check_cookies,
        "endpoints":   check_endpoints,
        "secret_leak": check_secret_leak,
        "auth":        check_auth,
    }

    all_findings: list[Finding] = []

    # ── Run all checks concurrently ───────────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        future_to_check = {
            executor.submit(run_check, name, func, url): name
            for name, func in checks.items()
        }

        for future in concurrent.futures.as_completed(future_to_check):
            check_name = future_to_check[future]
            try:
                findings = future.result(timeout=TIMEOUT + 5)
                all_findings.extend(findings)
            except concurrent.futures.TimeoutError:
                all_findings.append(Finding(
                    check_name=f"{check_name} scan",
                    category=check_name,
                    passed=False,
                    severity="info",
                    detail=f"{check_name} check timed out",
                    fix="No action needed — scan timed out",
                    evidence=None
                ))
            except Exception as e:
                all_findings.append(Finding(
                    check_name=f"{check_name} scan",
                    category=check_name,
                    passed=False,
                    severity="info",
                    detail=f"{check_name} check failed: {str(e)}",
                    fix="No action needed — internal scan error",
                    evidence=None
                ))

    result.findings = all_findings
    result.score, result.grade = calculate_score(all_findings)
    result.summary = build_summary(all_findings, result.score, result.grade)

    return format_result(result)


def run_check(name: str, func, url: str) -> list[Finding]:
    try:
        return func(url)
    except Exception as e:
        return [Finding(
            check_name=f"{name} scan",
            category=name,
            passed=False,
            severity="info",
            detail=f"Check failed unexpectedly: {str(e)}",
            fix="No action needed — internal error",
            evidence=None
        )]


def build_summary(findings: list[Finding], score: int, grade: str) -> str:
    critical = sum(1 for f in findings if f.severity == "critical" and not f.passed)
    high     = sum(1 for f in findings if f.severity == "high"     and not f.passed)
    medium   = sum(1 for f in findings if f.severity == "medium"   and not f.passed)
    low      = sum(1 for f in findings if f.severity == "low"      and not f.passed)

    parts = []
    if critical: parts.append(f"{critical} critical")
    if high:     parts.append(f"{high} high")
    if medium:   parts.append(f"{medium} medium")
    if low:      parts.append(f"{low} low")

    if not parts:
        return f"No issues found — Grade {grade} ({score}/100)"

    issues = ", ".join(parts)
    return f"{issues} issues found — Grade {grade} ({score}/100)"