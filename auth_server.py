from __future__ import annotations

import os
import time
from threading import Lock
from flask import Flask, jsonify, request, send_from_directory
from SuaAuth import SuaAuthApi

APP_ID = os.getenv('SUAUTH_APP_ID', '8f9fa0da-2fb8-4fc4-9d91-c74b41732964')
SECRET = os.getenv('SUAUTH_SECRET', 'sec_57bfdb388aa12f1f3ed8edfb78dffc6fad09daa52e07310cdbbc016db192b62b')
VERSION = os.getenv('SUAUTH_VERSION', '1.0')

app = Flask(__name__, static_folder='.', static_url_path='')

afterdeathapp = SuaAuthApi(
    app_id=APP_ID,
    secret=SECRET,
    version=VERSION,
)

afterdeathapp.init()

VISITOR_TTL = int(os.getenv('VISITOR_TTL', '30'))
VISITOR_LOCK = Lock()
VISITOR_LAST_SEEN: dict[str, float] = {}


def _get_client_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _cleanup_visitors(now: float) -> None:
    cutoff = now - VISITOR_TTL
    stale = [ip for ip, last_seen in VISITOR_LAST_SEEN.items() if last_seen < cutoff]
    for ip in stale:
        VISITOR_LAST_SEEN.pop(ip, None)


@app.after_request
def add_cors_headers(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return resp


@app.get('/')
def index():
    return send_from_directory('.', 'YhujinMovie.html')


@app.post('/auth/login')
def auth_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'success': False, 'message': 'Usuário e senha são obrigatórios.'}), 400

    res = afterdeathapp.login(username, password)
    if isinstance(res, dict):
        return jsonify(res)

    return jsonify({'success': False, 'message': 'Resposta inválida do servidor de autenticação.'}), 500


@app.post('/api/visitors/ping')
def visitors_ping():
    ip = _get_client_ip()
    now = time.time()
    with VISITOR_LOCK:
        VISITOR_LAST_SEEN[ip] = now
        _cleanup_visitors(now)
        count = len(VISITOR_LAST_SEEN)
    return jsonify({'count': count})


@app.get('/api/visitors/count')
def visitors_count():
    now = time.time()
    with VISITOR_LOCK:
        _cleanup_visitors(now)
        count = len(VISITOR_LAST_SEEN)
    return jsonify({'count': count})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)

