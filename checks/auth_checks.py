import uuid
import concurrent.futures

from core.models import Finding
from config import HEADERS
from core.http_client import safe_request

PROBE_WORKERS = 6

DEFAULT_CREDENTIALS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "123456"},
]


def check_auth(url: str) -> list[Finding]:
    findings = []
    base_url = url.rstrip("/")
    baseline_length = _get_baseline_length(base_url)

    admin_paths = [
        "/admin",
        "/admin/dashboard",
        "/admin/users",
        "/dashboard",
        "/manage",
        "/panel",
    ]

    api_paths = [
        "/api/users",
        "/api/admin",
        "/api/config",
        "/api/settings",
        "/api/v1/users",
        "/api/v2/users",
    ]

    login_paths = [
        "/login",
        "/admin/login",
        "/wp-login.php",
    ]

    probe_tasks = []
    for path in admin_paths:
        probe_tasks.append(("admin", path))
    for path in api_paths:
        probe_tasks.append(("api", path))
    for path in login_paths:
        probe_tasks.append(("login", path))

    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as executor:
        futures = []
        for probe_type, path in probe_tasks:
            if probe_type == "admin":
                futures.append(executor.submit(probe_auth_required, base_url, path, baseline_length))
            elif probe_type == "api":
                futures.append(executor.submit(probe_api_auth, base_url, path, baseline_length))
            else:
                futures.append(executor.submit(probe_default_credentials, base_url, path))

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    findings.append(result)
            except Exception:
                continue

    if not findings:
        findings.append(Finding(
            check_name="Auth Checks",
            category="auth",
            passed=True,
            severity="info",
            detail="No obvious authentication issues detected",
            fix="No action needed",
            evidence=None,
        ))

    return findings


def _get_baseline_length(base_url: str) -> int | None:
    baseline_path = f"/watchdog-auth-test-{uuid.uuid4().hex}"
    try:
        baseline_resp = safe_request(
            "GET",
            f"{base_url}{baseline_path}",
            headers=HEADERS,
            allow_redirects=False,
        )
        if baseline_resp.status_code == 200:
            return len(baseline_resp.content)
    except Exception:
        pass
    return None


def probe_auth_required(base_url: str, path: str, baseline_length: int | None = None) -> Finding | None:
    full_url = f"{base_url}{path}"

    try:
        response = safe_request(
            "GET",
            full_url,
            headers=HEADERS,
            allow_redirects=False,
        )
    except Exception:
        return None

    status = response.status_code

    if status == 200:
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
            evidence=f"GET {full_url} → {status}",
        )

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
                evidence=f"GET {full_url} → {status} → {location}",
            )

    return None


def probe_api_auth(base_url: str, path: str, baseline_length: int | None = None) -> Finding | None:
    full_url = f"{base_url}{path}"

    try:
        response = safe_request(
            "GET",
            full_url,
            headers=HEADERS,
            allow_redirects=False,
        )
    except Exception:
        return None

    status = response.status_code

    if status != 200:
        return None

    if baseline_length is not None:
        content_len = len(response.content)
        if baseline_length > 0:
            diff_ratio = abs(content_len - baseline_length) / baseline_length
            if diff_ratio < 0.10:
                return None
        elif content_len == 0:
            return None

    content_type = response.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            data = response.json()
            if data and (isinstance(data, list) and len(data) > 0
                         or isinstance(data, dict) and len(data) > 0):
                return Finding(
                    check_name=f"Unauthenticated API Endpoint: {path}",
                    category="auth",
                    passed=False,
                    severity="high",
                    detail=f"{path} returns JSON data without authentication. User data may be publicly readable.",
                    fix=f"Add authentication to {path}. Check for Authorization header or valid session cookie before returning data.",
                    evidence=f"GET {full_url} → 200 JSON ({len(str(data))} chars)",
                )
        except Exception:
            return None

    return None


def probe_default_credentials(base_url: str, path: str) -> Finding | None:
    full_url = f"{base_url}{path}"

    try:
        response = safe_request(
            "GET",
            full_url,
            headers=HEADERS,
            allow_redirects=False,
        )
    except Exception:
        return None

    if response.status_code != 200:
        return None

    for creds in DEFAULT_CREDENTIALS:
        for content_type, body in (
            ("json", {"json": creds}),
            ("form", {"data": creds}),
        ):
            try:
                headers = {**HEADERS}
                if content_type == "json":
                    headers["Content-Type"] = "application/json"
                post_response = safe_request(
                    "POST",
                    full_url,
                    headers=headers,
                    allow_redirects=False,
                    **body,
                )
                if post_response.status_code in (301, 302, 303, 307, 308):
                    location = post_response.headers.get("location", "")
                    if "login" not in location.lower():
                        return Finding(
                            check_name=f"Default Credentials Work: {path}",
                            category="auth",
                            passed=False,
                            severity="critical",
                            detail=f"Login at {path} accepted default credentials: {creds['username']}:{creds['password']}",
                            fix="Change default credentials immediately. Enforce strong password policy. Consider adding rate limiting and 2FA.",
                            evidence=f"POST {full_url} ({content_type}) with {creds['username']}:{creds['password']} → {post_response.status_code}",
                        )
                if post_response.status_code == 200 and content_type == "json":
                    try:
                        data = post_response.json()
                        if isinstance(data, dict) and data.get("token"):
                            return Finding(
                                check_name=f"Default Credentials Work: {path}",
                                category="auth",
                                passed=False,
                                severity="critical",
                                detail=f"Login at {path} returned a token for default credentials: {creds['username']}:{creds['password']}",
                                fix="Change default credentials immediately. Enforce strong password policy. Consider adding rate limiting and 2FA.",
                                evidence=f"POST {full_url} ({content_type}) with {creds['username']}:{creds['password']} → 200 token response",
                            )
                    except Exception:
                        pass
            except Exception:
                continue

    return None
