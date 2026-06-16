import re
import requests
from bs4 import BeautifulSoup
from core.models import Finding
from config import TIMEOUT, HEADERS, SECRET_PATTERNS
from core.http_client import safe_request, SafeRequestException

def check_secret_leak(url: str) -> list[Finding]:
    findings = []

    # ── Fetch main page ───────────────────────────────────────
    try:
        response = safe_request(
            'GET',
            url,
            headers=HEADERS,
            allow_redirects=True
        )
    except SafeRequestException as e:
        return [Finding(
            check_name="Secret Leak Scan",
            category="secret_leak",
            passed=False,
            severity="critical",
            detail=f"Connection failed: {str(e)}",
            fix="Check the URL is correct and the site is live",
            evidence=None
        )]

    # ── Collect all sources to scan ───────────────────────────
    sources = []
    sources.append(("main page", response.text))

    js_urls = extract_js_urls(url, response.text)
    for js_url in js_urls[:5]:  # cap at 5 JS files to avoid timeout
        js_content = fetch_js(js_url)
        if js_content:
            sources.append((js_url, js_content))

    # ── Scan all sources for secrets ──────────────────────────
    leaked = []
    for source_name, content in sources:
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                leaked.append((secret_type, source_name, matches[0]))

    # ── Build findings ────────────────────────────────────────
    if not leaked:
        findings.append(Finding(
            check_name="Secret Leak",
            category="secret_leak",
            passed=True,
            severity="info",
            detail="No exposed API keys or secrets detected in page source or JS files",
            fix="No action needed",
            evidence=None
        ))
        return findings

    for secret_type, source_name, match in leaked:
        redacted = redact(match)
        findings.append(Finding(
            check_name=f"Exposed Secret: {secret_type}",
            category="secret_leak",
            passed=False,
            severity="critical",
            detail=f"Potential {secret_type} found in {source_name}",
            fix=get_fix(secret_type),
            evidence=redacted
        ))

    return findings


def extract_js_urls(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    js_urls = []

    for tag in soup.find_all("script", src=True):
        src = tag["src"]

        # handle relative URLs
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            base = base_url.rstrip("/")
            src = base + src
        elif not src.startswith("http"):
            src = base_url.rstrip("/") + "/" + src

        js_urls.append(src)

    return js_urls


def fetch_js(url: str) -> str | None:
    try:
        response = safe_request(
            'GET',
            url,
            headers=HEADERS
        )
        if response.status_code == 200:
            return response.text
        return None
    except Exception:
        return None


def redact(match: str) -> str:
    # show first 6 and last 4 chars only — enough to identify, not enough to use
    if len(match) <= 10:
        return "***REDACTED***"
    return match[:6] + "..." + match[-4:]


def get_fix(secret_type: str) -> str:
    fixes = {
        "openai_api_key": "Revoke this OpenAI key immediately at platform.openai.com/api-keys. Move it to an environment variable. Never hardcode API keys in frontend code.",
        "stripe_secret": "Revoke this Stripe key immediately at dashboard.stripe.com/apikeys. Stripe secret keys must never appear in frontend code or public repos.",
        "stripe_public": "Stripe publishable keys are less sensitive but should still not be hardcoded. Move to environment variable.",
        "supabase_key": "Rotate this Supabase key at app.supabase.com. Move to environment variable. Check Row Level Security is enabled.",
        "aws_access_key": "Revoke this AWS key immediately at aws.amazon.com/iam. Check CloudTrail for unauthorized usage. Move credentials to IAM roles.",
        "aws_secret": "Revoke this AWS secret immediately. Check CloudTrail logs for any unauthorized API calls made with this key.",
        "github_token": "Revoke this GitHub token at github.com/settings/tokens. Tokens in frontend code can be used to access your repositories.",
        "google_api_key": "Restrict this Google API key at console.cloud.google.com/apis/credentials. Add HTTP referrer restrictions so it cannot be used from other domains.",
    }
    return fixes.get(secret_type, "Revoke and rotate this credential immediately. Move it to an environment variable on your server.")