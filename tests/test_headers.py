import pytest
import responses
from checks.headers import check_headers

@responses.activate
def test_all_headers_present():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()"
        },
        status=200
    )
    
    findings = check_headers(url)
    assert len(findings) == 6
    assert all(f.passed is True for f in findings)

@responses.activate
def test_missing_x_frame_options_no_csp_fallback():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()"
        },
        status=200
    )
    
    findings = check_headers(url)
    xframe_finding = next(f for f in findings if f.check_name == "X-Frame-Options")
    assert xframe_finding.passed is False
    assert xframe_finding.severity == "low"

@responses.activate
def test_missing_x_frame_options_with_csp_fallback():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        headers={
            "content-security-policy": "frame-ancestors 'none'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()"
        },
        status=200
    )
    
    findings = check_headers(url)
    xframe_finding = next(f for f in findings if f.check_name == "X-Frame-Options")
    # Should pass because of CSP frame-ancestors fallback
    assert xframe_finding.passed is True
    assert xframe_finding.severity == "info"
    assert xframe_finding.confidence == "high"
