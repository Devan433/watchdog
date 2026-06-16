from core.models import Finding
from config import SEVERITY_WEIGHTS, GRADE_THRESHOLDS

def calculate_score(findings: list[Finding]) -> tuple[int, str]:

    # ── Separate passed and failed ────────────────────────────
    failed = [f for f in findings if not f.passed]

    if not failed:
        return 100, "A"

    # ── Calculate penalty ─────────────────────────────────────
    total_penalty = 0

    for finding in failed:
        severity = finding.severity.lower()
        penalty = SEVERITY_WEIGHTS.get(severity, 0)
        total_penalty += penalty

    # ── Calculate raw score ───────────────────────────────────
    raw_score = 100 - total_penalty

    # clamp between 0 and 100 — penalty can exceed 100 on bad sites
    score = max(0, min(100, raw_score))

    # ── Assign grade ──────────────────────────────────────────
    grade = calculate_grade(score)

    return score, grade


def calculate_grade(score: int) -> str:
    if score >= GRADE_THRESHOLDS["A"]:
        return "A"
    if score >= GRADE_THRESHOLDS["B"]:
        return "B"
    if score >= GRADE_THRESHOLDS["C"]:
        return "C"
    if score >= GRADE_THRESHOLDS["D"]:
        return "D"
    return "F"


def get_severity_breakdown(findings: list[Finding]) -> dict:
    breakdown = {
        "critical": 0,
        "high":     0,
        "medium":   0,
        "low":      0,
        "info":     0,
        "passed":   0,
    }

    for finding in findings:
        if finding.passed:
            breakdown["passed"] += 1
        else:
            severity = finding.severity.lower()
            if severity in breakdown:
                breakdown[severity] += 1

    return breakdown