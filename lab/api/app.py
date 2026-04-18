"""Intentionally-insecure Flask API stub for the ShadowTrace lab.

Exposes:
  - GET  /           banner + version (verbose, leaks stack hint)
  - POST /login      stub auth; stores a session token in Redis (no auth on Redis)
  - GET  /config     returns non-secret runtime config; leaks DB host + user
  - GET  /healthz    liveness probe

The DB password is intentionally read from a plaintext env var so the scanner
and lab validator have a concrete artifact to point at when the CRED-001 edge
rule fires.
"""
import os
import secrets

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "shadowlab-mysql")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "shadowlab_root_2024")
REDIS_HOST = os.environ.get("REDIS_HOST", "shadowlab-redis")

_redis = redis.Redis(host=REDIS_HOST, port=6379, socket_connect_timeout=2)


@app.get("/")
def index():
    return jsonify({
        "service": "shadowlab-api",
        "version": "0.1.0",
        "framework": "Flask 2.0.1",
        "runtime": "Python 3.8",
    })


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("username", "")
    token = secrets.token_hex(16)
    try:
        _redis.setex(f"session:{token}", 3600, user or "anonymous")
    except Exception as exc:
        return jsonify({"error": "session store unreachable", "detail": str(exc)}), 500
    return jsonify({"token": token, "user": user})


@app.get("/config")
def config():
    return jsonify({
        "db_host": DB_HOST,
        "db_user": DB_USER,
        "redis_host": REDIS_HOST,
        "debug": True,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
