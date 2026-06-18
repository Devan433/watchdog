import pytest
import responses
import re
from checks.secret_leak import check_secret_leak, is_third_party

def test_is_third_party():
    assert is_third_party("main page") is False
    assert is_third_party("https://example.com/script.js") is False
    assert is_third_party("https://mycdn.example.com/lib.js") is False
    assert is_third_party("https://cdnjs.cloudflare.com/ajax/libs/react/17.0.2/umd/react.production.min.js") is True
    assert is_third_party("https://maps.googleapis.com/maps/api/js?key=123") is True

@responses.activate
def test_no_secrets_found():
    url = "https://example.com"
    responses.add(
        responses.GET,
        url,
        body="<html><body><h1>Hello World</h1></body></html>",
        status=200
    )
    
    findings = check_secret_leak(url)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].check_name == "Secret Leak"

@responses.activate
def test_first_party_secret_leak():
    url = "https://example.com"
    html = "<html><body><script src='/app.js'></script></body></html>"
    
    responses.add(responses.GET, url, body=html, status=200)
    
    # Mock the JS file containing an OpenAI key
    js_content = "const OPENAI_API_KEY = 'sk-abdef01234abcdef01234abcdef01234abcdef01234';"
    responses.add(responses.GET, "https://example.com/app.js", body=js_content, status=200)
    
    findings = check_secret_leak(url)
    failed = [f for f in findings if not f.passed]
    assert len(failed) == 1
    
    secret_finding = failed[0]
    assert "openai_api_key" in secret_finding.check_name
    assert secret_finding.severity == "critical"
    assert secret_finding.confidence == "high"
    assert secret_finding.is_third_party is False

@responses.activate
def test_third_party_secret_leak_downgraded():
    url = "https://example.com"
    html = "<html><body><script src='https://cdnjs.cloudflare.com/lib.js'></script></body></html>"
    
    responses.add(responses.GET, url, body=html, status=200)
    
    # Mock the JS file containing an OpenAI key
    js_content = "const exampleKey = 'sk-abdef01234abcdef01234abcdef01234abcdef01234';"
    responses.add(responses.GET, "https://cdnjs.cloudflare.com/lib.js", body=js_content, status=200)
    
    findings = check_secret_leak(url)
    failed = [f for f in findings if not f.passed]
    assert len(failed) == 1
    
    secret_finding = failed[0]
    assert "openai_api_key" in secret_finding.check_name
    # Should be downgraded because it's a 3rd party domain
    assert secret_finding.severity == "info"
    assert secret_finding.confidence == "low"
    assert secret_finding.is_third_party is True

@responses.activate
def test_dummy_key_filtering():
    url = "https://example.com"
    # Contains a string that matches AWS secret pattern but has 'example'
    html = "<html><body>aws_secret='example_0123456789abcdef0123456789abcdef'</body></html>"
    
    responses.add(responses.GET, url, body=html, status=200)
    
    findings = check_secret_leak(url)
    assert len(findings) == 1
    assert findings[0].passed is True  # Dummy key should be filtered out
