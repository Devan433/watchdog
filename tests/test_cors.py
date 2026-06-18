import pytest
import responses
from checks.cors import check_cors

@responses.activate
def test_cors_wildcard_with_credentials():
    url = "https://example.com/api"
    responses.add(
        responses.GET,
        url,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        },
        status=200
    )
    
    findings = check_cors(url)
    assert len(findings) == 1
    assert findings[0].check_name == "CORS Wildcard With Credentials"
    assert findings[0].severity == "critical"
    assert findings[0].confidence == "high"

@responses.activate
def test_cors_wildcard_only():
    url = "https://example.com/api"
    responses.add(
        responses.GET,
        url,
        headers={
            "Access-Control-Allow-Origin": "*"
        },
        status=200
    )
    
    findings = check_cors(url)
    assert len(findings) == 1
    assert findings[0].check_name == "CORS Wildcard Origin"
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "low"

@responses.activate
def test_cors_origin_reflection():
    url = "https://example.com/api"
    responses.add(
        responses.GET,
        url,
        headers={
            "Access-Control-Allow-Origin": "https://evil.com"
        },
        status=200
    )
    
    findings = check_cors(url)
    assert len(findings) == 1
    assert findings[0].check_name == "CORS Origin Reflection"
    assert findings[0].severity == "high"
    assert findings[0].confidence == "medium"

@responses.activate
def test_cors_no_headers():
    url = "https://example.com/api"
    responses.add(
        responses.GET,
        url,
        status=200
    )
    
    findings = check_cors(url)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == "info"

@responses.activate
def test_cors_specific_origin():
    url = "https://example.com/api"
    responses.add(
        responses.GET,
        url,
        headers={
            "Access-Control-Allow-Origin": "https://trusted.com"
        },
        status=200
    )
    
    findings = check_cors(url)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == "info"
