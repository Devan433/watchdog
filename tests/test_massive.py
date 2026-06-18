import pytest
from core.models import Finding
from core.scorer import calculate_score

# This creates exactly 5 x 2 x 3 x 10 = 300 test cases!
# It tests every severity level, passing and failing, confidence levels, with 1 to 10 findings each.
@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
@pytest.mark.parametrize("passed", [True, False])
@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
@pytest.mark.parametrize("count", range(1, 11))
def test_massive_scoring_permutations(severity, passed, confidence, count):
    findings = [Finding(
        check_name=f"test_{i}",
        category="test",
        passed=passed,
        severity=severity,
        detail="detail",
        fix="fix",
        confidence=confidence,
        is_third_party=False
    ) for i in range(count)]
    
    score, grade = calculate_score(findings)
    
    # Assertions to ensure the math always holds up regardless of input volume
    assert 0 <= score <= 100, f"Score {score} is out of bounds!"
    assert grade in ["A", "B", "C", "D", "F"], f"Grade {grade} is invalid!"
    
    if passed:
        assert score == 100
        assert grade == "A"
    else:
        if severity == "info":
            assert score == 100
            assert grade == "A"
        elif severity == "low":
            # Penalty capped at 15
            expected_penalty = min(count * 3, 15)
            assert score == 100 - expected_penalty
        elif severity == "critical":
            # 30 penalty per critical finding
            expected_score = max(0, 100 - (count * 30))
            assert score == expected_score
