import os
import re
import sys
import json
import argparse
import threading
import logging

from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from core.orchestrator import run_scan
from core.http_client import set_allow_localhost

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded. Please try again later.", detail=str(e.description)), 429

MAX_CONCURRENT_SCANS = 10
scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)

@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

def is_valid_url(url: str, *, allow_localhost: bool = False) -> bool:
    if allow_localhost:
        localhost_pattern = re.compile(
            r"^https?://localhost(?::\d+)?(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        if localhost_pattern.match(url):
            return True
    pattern = re.compile(
        r"^https?://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\.?)"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return bool(pattern.match(url))

def validate_scan_url(url: str, *, allow_localhost: bool = False) -> tuple[str | None, str | None]:
    if not url:
        return "No URL provided", None
    if not isinstance(url, str):
        return "URL must be a string", None
    url = url.strip()
    if len(url) > 2048:
        return "URL exceeds maximum length", None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not is_valid_url(url, allow_localhost=allow_localhost):
        return "Invalid URL format. Must be a public domain (http:// or https://)", None
    return None, url

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
@limiter.limit("5 per minute")
def scan():
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided or invalid JSON"}), 400

    error, url = validate_scan_url(data["url"])
    if error:
        return jsonify({"error": error}), 400

    acquired = scan_semaphore.acquire(blocking=False)
    if not acquired:
        return jsonify({"error": "Server is busy. Please try again in a few seconds."}), 503

    try:
        result = run_scan(url)
        if result.get("error"):
            return jsonify(result), 502
        return jsonify(result)
    finally:
        scan_semaphore.release()


def run_cli():
    parser = argparse.ArgumentParser(description="Watchdog security linter")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--fail-under", type=int, default=0, help="Exit 1 if score is below this value")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")
    parser.add_argument("--allow-localhost", action="store_true", help="Allow scanning localhost (CLI only)")
    args = parser.parse_args()

    set_allow_localhost(args.allow_localhost)
    error, url = validate_scan_url(args.url, allow_localhost=args.allow_localhost)
    if error:
        print(error, file=sys.stderr)
        sys.exit(2)

    result = run_scan(url)
    if result.get("error"):
        print(result["error"], file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"URL: {result['url']}")
        print(f"Score: {result['score']}/100 (Grade {result['grade']})")
        print(result["summary"])
        b = result["breakdown"]
        print(f"  Critical: {b['critical']}  High: {b['high']}  Medium: {b['medium']}  Low: {b['low']}")

    if args.fail_under and result["score"] < args.fail_under:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        sys.argv.pop(1)
        run_cli()
    else:
        port = int(os.environ.get("PORT", 5000))
        from waitress import serve
        print(f"Starting Waitress production server on port {port}...")
        serve(app, host="0.0.0.0", port=port, threads=16)
