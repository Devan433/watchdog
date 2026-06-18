import pytest
import responses
from checks.endpoints import check_endpoints

@responses.activate
def test_no_endpoints_exposed():
    url = "https://example.com"
    # Mock all endpoints to return 404
    responses.add(responses.GET, "https://example.com/watchdog-404-test", status=404)
    responses.add(responses.GET, "https://example.com/.env", status=404)
    responses.add(responses.GET, "https://example.com/.git/config", status=404)
    responses.add(responses.GET, "https://example.com/admin", status=404)
    responses.add(responses.GET, "https://example.com/admin/login", status=404)
    responses.add(responses.GET, "https://example.com/api/users", status=404)
    responses.add(responses.GET, "https://example.com/api/keys", status=404)
    responses.add(responses.GET, "https://example.com/phpinfo.php", status=404)
    responses.add(responses.GET, "https://example.com/config.php", status=404)
    responses.add(responses.GET, "https://example.com/backup.sql", status=404)
    responses.add(responses.GET, "https://example.com/wp-admin", status=404)
    responses.add(responses.GET, "https://example.com/dashboard", status=404)
    
    # We just mock the generic catch-all
    responses.add_callback(
        responses.GET,
        re.compile("https://example.com/.*"),
        callback=lambda request: (404, {}, "Not Found")
    )
    
    findings = check_endpoints(url)
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].check_name == "Sensitive Endpoints"

import re

@responses.activate
def test_exposed_env_file():
    url = "https://example.com"
    
    def request_callback(request):
        if request.url == "https://example.com/.env":
            return (200, {}, "DB_PASSWORD=supersecret")
        return (404, {}, "Not Found")

    responses.add_callback(
        responses.GET,
        re.compile("https://example.com/.*"),
        callback=request_callback
    )
    
    findings = check_endpoints(url)
    failed = [f for f in findings if not f.passed]
    assert len(failed) == 1
    assert failed[0].check_name == "Exposed Endpoint: /.env"
    assert failed[0].severity == "critical"
    assert failed[0].confidence == "high"

@responses.activate
def test_spa_false_positive():
    url = "https://example.com"
    
    # Simulate an SPA that returns the same index.html for every route
    spa_html = "<html><body><div id='root'>Not Found Page</div></body></html>"
    
    def request_callback(request):
        return (200, {}, spa_html)

    responses.add_callback(
        responses.GET,
        re.compile("https://example.com/.*"),
        callback=request_callback
    )
    
    findings = check_endpoints(url)
    
    # Should not report any criticals since baseline diff is 0 and it has "Not Found"
    criticals = [f for f in findings if f.severity == "critical"]
    assert len(criticals) == 0

@responses.activate
def test_git_config_validation():
    url = "https://example.com"
    
    def request_callback(request):
        if request.url == "https://example.com/.git/config":
            # Returns 200, but doesn't look like a real git config
            return (200, {}, "Just an empty page or weird 200")
        return (404, {}, "Not Found")

    responses.add_callback(
        responses.GET,
        re.compile("https://example.com/.*"),
        callback=request_callback
    )
    
    findings = check_endpoints(url)
    git_finding = next((f for f in findings if not f.passed and "/.git/config" in f.check_name), None)
    
    assert git_finding is not None
    # Because it lacks [core], it should be downgraded
    assert git_finding.confidence == "low"
    assert git_finding.severity == "info"

@responses.activate
def test_real_git_config():
    url = "https://example.com"
    
    def request_callback(request):
        if request.url == "https://example.com/.git/config":
            return (200, {}, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true")
        return (404, {}, "Not Found")

    responses.add_callback(
        responses.GET,
        re.compile("https://example.com/.*"),
        callback=request_callback
    )
    
    findings = check_endpoints(url)
    git_finding = next((f for f in findings if not f.passed and "/.git/config" in f.check_name), None)
    
    assert git_finding is not None
    # Contains [core], so should be highly confident
    assert git_finding.confidence == "high"
    assert git_finding.severity == "critical"
