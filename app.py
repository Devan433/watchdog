from flask import Flask, request, jsonify, render_template
from core.orchestrator import run_scan
import re

app = Flask(__name__)

# ── URL validation ─────────────────────────────────────────────
def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(pattern.match(url))

# ── Routes ─────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400

    url = data['url'].strip()

    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL. Must start with http:// or https://'}), 400

    result = run_scan(url)
    return jsonify(result)

# ── Run ────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)