from core.models import ScanResult, Finding
from core.scorer import get_severity_breakdown

def format_result(result: ScanResult) -> dict:

    breakdown = get_severity_breakdown(result.findings)

    # ── Group findings by category ────────────────────────────
    categories = {}
    for finding in result.findings:
        cat = finding.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(format_finding(finding))

    # ── Build final response ──────────────────────────────────
    return {
        "url":      result.url,
        "score":    result.score,
        "grade":    result.grade,
        "summary":  result.summary,
        "breakdown": {
            "critical": breakdown["critical"],
            "high":     breakdown["high"],
            "medium":   breakdown["medium"],
            "low":      breakdown["low"],
            "passed":   breakdown["passed"],
        },
        "categories": categories,
        "error":    result.error,
    }


def format_finding(finding: Finding) -> dict:
    return {
        "check_name": finding.check_name,
        "passed":     finding.passed,
        "severity":   finding.severity,
        "detail":     finding.detail,
        "fix":        finding.fix,
        "evidence":   finding.evidence,
        "fix_prompt": build_fix_prompt(finding),
    }


def build_fix_prompt(finding: Finding) -> str | None:
    if finding.passed:
        return None

    return (
        f"Fix this security issue in my web app:\n\n"
        f"Issue: {finding.check_name}\n"
        f"Detail: {finding.detail}\n"
        f"Evidence: {finding.evidence or 'N/A'}\n\n"
        f"Fix: {finding.fix}\n\n"
        f"Please show me exactly how to implement this fix in my codebase."
    )


def format_error(url: str, error: str) -> dict:
    return {
        "url":      url,
        "score":    0,
        "grade":    "F",
        "summary":  "Scan failed — could not reach the target URL",
        "breakdown": {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "low":      0,
            "passed":   0,
        },
        "categories": {},
        "error":    error,
    }