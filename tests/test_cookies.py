import pytest
import responses
from checks.cookies import check_cookies

@responses.activate
def test_no_cookies():
    url = "https://example.com"
    responses.add(responses.GET, url, status=200)
    findings = check_cookies(url)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].detail == "No cookies set by this page"

@responses.activate
def test_session_cookie_missing_httponly():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={"Set-Cookie": "session_id=123; Secure; SameSite=Strict"},
        status=200
    )
    findings = check_cookies(url)
    # Findings should be: HttpOnly (fail), Secure (pass), SameSite (pass)
    httponly_finding = next(f for f in findings if "HttpOnly" in f.check_name)
    assert httponly_finding.passed is False
    assert httponly_finding.severity == "high"
    assert httponly_finding.confidence == "high"

@responses.activate
def test_tracking_cookie_missing_httponly():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={"Set-Cookie": "_ga=123; Secure; SameSite=Strict"},
        status=200
    )
    findings = check_cookies(url)
    httponly_finding = next(f for f in findings if "HttpOnly" in f.check_name)
    assert httponly_finding.passed is False
    assert httponly_finding.severity == "info"
    assert httponly_finding.confidence == "low"

@responses.activate
def test_cookie_missing_secure():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={"Set-Cookie": "auth_token=123; HttpOnly; SameSite=Strict"},
        status=200
    )
    findings = check_cookies(url)
    secure_finding = next(f for f in findings if "Secure" in f.check_name)
    assert secure_finding.passed is False
    assert secure_finding.severity == "medium"

@responses.activate
def test_cookie_missing_samesite():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={"Set-Cookie": "auth_token=123; HttpOnly; Secure"},
        status=200
    )
    findings = check_cookies(url)
    samesite_finding = next(f for f in findings if "SameSite" in f.check_name)
    assert samesite_finding.passed is False
    assert samesite_finding.severity == "low"

@responses.activate
def test_perfect_cookie():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={"Set-Cookie": "auth_token=123; HttpOnly; Secure; SameSite=Lax"},
        status=200
    )
    findings = check_cookies(url)
    assert all(f.passed is True for f in findings)
