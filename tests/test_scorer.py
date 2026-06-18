import pytest
from core.models import Finding
from core.scorer import calculate_score, calculate_grade, get_severity_breakdown

def create_finding(passed=False, severity="low"):
    return Finding(
        check_name="Test",
        category="test",
        passed=passed,
        severity=severity,
        detail="detail",
        fix="fix"
    )

def test_calculate_score_all_passed():
    findings = [create_finding(passed=True, severity="info") for _ in range(5)]
    score, grade = calculate_score(findings)
    assert score == 100
    assert grade == "A"

def test_calculate_score_critical_penalty():
    findings = [create_finding(passed=False, severity="critical")]
    score, grade = calculate_score(findings)
    assert score == 70  # 100 - 30
    assert grade == "C"

def test_calculate_score_low_penalty_cap():
    # 10 low findings = 30 penalty, but max low penalty is 15
    findings = [create_finding(passed=False, severity="low") for _ in range(10)]
    score, grade = calculate_score(findings)
    assert score == 85  # 100 - 15
    assert grade == "B"

def test_calculate_score_clamping():
    # 4 criticals = 120 penalty
    findings = [create_finding(passed=False, severity="critical") for _ in range(4)]
    score, grade = calculate_score(findings)
    assert score == 0  # clamped from -20
    assert grade == "F"

def test_calculate_grade():
    assert calculate_grade(95) == "A"
    assert calculate_grade(90) == "A"
    assert calculate_grade(89) == "B"
    assert calculate_grade(75) == "B"
    assert calculate_grade(74) == "C"
    assert calculate_grade(60) == "C"
    assert calculate_grade(59) == "D"
    assert calculate_grade(45) == "D"
    assert calculate_grade(44) == "F"
    assert calculate_grade(0) == "F"

def test_severity_breakdown():
    findings = [
        create_finding(passed=True),
        create_finding(passed=True),
        create_finding(passed=False, severity="critical"),
        create_finding(passed=False, severity="medium"),
        create_finding(passed=False, severity="medium"),
        create_finding(passed=False, severity="info")
    ]
    breakdown = get_severity_breakdown(findings)
    assert breakdown["passed"] == 2
    assert breakdown["critical"] == 1
    assert breakdown["high"] == 0
    assert breakdown["medium"] == 2
    assert breakdown["low"] == 0
    assert breakdown["info"] == 1
