import os
import re
import threading
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from core.orchestrator import run_scan

app = Flask(__name__)

# Trust the X-Forwarded-For header from Render/reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ── Rate limiting ──────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded. Please try again later.", detail=str(e.description)), 429

# ── Concurrency control ───────────────────────────────────────
MAX_CONCURRENT_SCANS = 10
scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)

# ── Security Headers ──────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# ── URL validation ─────────────────────────────────────────────
def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(pattern.match(url))

# ── Routes ─────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@limiter.limit("5 per minute")
def scan():
    data = request.get_json(silent=True)

    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided or invalid JSON'}), 400

    if not isinstance(data['url'], str):
        return jsonify({'error': 'URL must be a string'}), 400

    url = data['url'].strip()

    if len(url) > 2048:
        return jsonify({'error': 'URL exceeds maximum length'}), 400

    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL format. Must be a public domain (http:// or https://)'}), 400

    # Enforce concurrency limit
    acquired = scan_semaphore.acquire(blocking=False)
    if not acquired:
        return jsonify({'error': 'Server is busy. Please try again in a few seconds.'}), 503

    try:
        result = run_scan(url)
        return jsonify(result)
    finally:
        scan_semaphore.release()

# ── Run ────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    from waitress import serve
    print(f"Starting Waitress production server on port {port}...")
    serve(app, host='0.0.0.0', port=port, threads=16)