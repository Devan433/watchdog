import uuid
import requests
from core.models import Finding
from config import TIMEOUT, HEADERS
from core.http_client import safe_request, SafeRequestException

def check_auth(url: str) -> list[Finding]:
    findings = []

    base_url = url.rstrip("/")

    # ── Establish 404 Baseline (SPA False Positive Check) ─────
    baseline_length = None
    baseline_path = f"/watchdog-auth-test-{uuid.uuid4().hex}"
    try:
        baseline_resp = safe_request(
            'GET',
            f"{base_url}{baseline_path}",
            headers=HEADERS,
            allow_redirects=False
        )
        if baseline_resp.status_code == 200:
            baseline_length = len(baseline_resp.content)
    except Exception:
        pass

    # ── Check 1: Admin routes without auth ────────────────────
    admin_paths = [
        "/admin",
        "/admin/dashboard",
        "/admin/users",
        "/dashboard",
        "/manage",
        "/panel",
    ]

    for path in admin_paths:
        result = probe_auth_required(base_url, path, baseline_length)
        if result:
            findings.append(result)

    # ── Check 2: API endpoints without auth ───────────────────
    api_paths = [
        "/api/users",
        "/api/admin",
        "/api/config",
        "/api/settings",
        "/api/v1/users",
        "/api/v2/users",
    ]

    for path in api_paths:
        result = probe_api_auth(base_url, path, baseline_length)
        if result:
            findings.append(result)

    # ── Check 3: Common default credentials ───────────────────
    login_paths = [
        "/login",
        "/admin/login",
        "/wp-login.php",
    ]

    for path in login_paths:
        result = probe_default_credentials(base_url, path)
        if result:
            findings.append(result)

    # ── No issues found ───────────────────────────────────────
    if not findings:
        findings.append(Finding(
            check_name="Auth Checks",
            category="auth",
            passed=True,
            severity="info",
            detail="No obvious authentication issues detected",
            fix="No action needed",
            evidence=None
        ))

    return findings


def probe_auth_required(base_url: str, path: str, baseline_length: int | None = None) -> Finding | None:
    full_url = f"{base_url}{path}"

    try:
        # first request: no cookies, no auth headers
        response = safe_request(
            'GET',
            full_url,
            headers=HEADERS,
            allow_redirects=False
        )
    except Exception:
        return None

    status = response.status_code

    # 200 with no auth = potential problem
    if status == 200:
        # SPA false positive check — if response matches the baseline 404 page, skip it
        if baseline_length is not None:
            content_len = len(response.content)
            if baseline_length > 0:
                diff_ratio = abs(content_len - baseline_length) / baseline_length
                if diff_ratio < 0.10:
                    return None
            elif content_len == 0:
                return None

        return Finding(
            check_name=f"Unprotected Admin Route: {path}",
            category="auth",
            passed=False,
            severity="high",
            detail=f"{path} returned HTTP 200 without any authentication. Admin interface may be publicly accessible.",
            fix=f"Protect {path} with authentication middleware. In Flask: use @login_required decorator. In Express: use passport.js middleware.",
            evidence=f"GET {full_url} → {status}"
        )

    # 302 to login page = correctly protected
    if status == 302:
        location = response.headers.get("location", "")
        if "login" in location.lower() or "signin" in location.lower():
            return Finding(
                check_name=f"Admin Route Protected: {path}",
                category="auth",
                passed=True,
                severity="info",
                detail=f"{path} correctly redirects to login page",
                fix="No action needed",
                evidence=f"GET {full_url} → {status} → {location}"
            )

    return None


def probe_api_auth(base_url: str, path: str, baseline_length: int | None = None) -> Finding | None:
    full_url = f"{base_url}{path}"

    try:
        # request with no auth header and no cookies
        response = safe_request(
            'GET',
            full_url,
            headers=HEADERS,
            allow_redirects=False
        )
    except Exception:
        return None

    status = response.status_code

    if status != 200:
        return None

    # SPA false positive check
    if baseline_length is not None:
        content_len = len(response.content)
        if baseline_length > 0:
            diff_ratio = abs(content_len - baseline_length) / baseline_length
            if diff_ratio < 0.10:
                return None
        elif content_len == 0:
            return None

    # ── API returned 200 — check if it has real data ──────────
    content_type = response.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            data = response.json()
            # non-empty JSON response without auth = problem
            if data and (isinstance(data, list) and len(data) > 0
                         or isinstance(data, dict) and len(data) > 0):
                return Finding(
                    check_name=f"Unauthenticated API Endpoint: {path}",
                    category="auth",
                    passed=False,
                    severity="high",
                    detail=f"{path} returns JSON data without authentication. User data may be publicly readable.",
                    fix=f"Add authentication to {path}. Check for Authorization header or valid session cookie before returning data.",
                    evidence=f"GET {full_url} → 200 JSON ({len(str(data))} chars)"
                )
        except Exception:
            return None

    return None


def probe_default_credentials(base_url: str, path: str) -> Finding | None:
    full_url = f"{base_url}{path}"

    try:
        response = safe_request(
            'GET',
            full_url,
            headers=HEADERS,
            allow_redirects=False
        )
    except Exception:
        return None

    status = response.status_code

    # login page exists — try default credentials
    if status != 200:
        return None

    default_credentials = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "123456"},
    ]

    for creds in default_credentials:
        try:
            post_response = safe_request(
                'POST',
                full_url,
                json=creds,  # Use JSON since modern APIs expect it
                headers=HEADERS,
                allow_redirects=False
            )
            # successful login redirects away from login page
            if post_response.status_code in [301, 302]:
                location = post_response.headers.get("location", "")
                if "login" not in location.lower():
                    return Finding(
                        check_name=f"Default Credentials Work: {path}",
                        category="auth",
                        passed=False,
                        severity="critical",
                        detail=f"Login at {path} accepted default credentials: {creds['username']}:{creds['password']}",
                        fix="Change default credentials immediately. Enforce strong password policy. Consider adding rate limiting and 2FA.",
                        evidence=f"POST {full_url} with {creds['username']}:{creds['password']} → {post_response.status_code}"
                    )
        except Exception:
            continue

    return None