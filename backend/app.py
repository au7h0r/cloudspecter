import logging
import os

from flask import Flask, jsonify, request
import requests
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

app = Flask(__name__)

DEFAULT_TIMEOUT = float(os.getenv("FETCH_TIMEOUT_SECONDS", "5"))
APP_PORT = int(os.getenv("APP_PORT", "5000"))

logging.basicConfig(level=logging.INFO)

FETCH_REQUESTS = Counter(
    "cloudspecter_fetch_requests_total",
    "Total fetch requests handled by the vulnerable image fetch API",
    ["result"],
)

SSRF_ATTEMPTS = Counter(
    "cloudspecter_ssrf_attempts_total",
    "Total SSRF-style fetch attempts handled by the vulnerable image fetch API",
    ["result"],
)

FETCH_LATENCY = Histogram(
    "cloudspecter_fetch_request_duration_seconds",
    "Time spent handling fetch requests",
)


@app.get("/")
def index():
    return jsonify({
        "service": "CloudSpecter Image Fetch API",
        "status": "ok",
        "routes": ["/api/fetch?url=...", "/health"],
    })


@app.get("/health")
def health():
    return jsonify({"status": "healthy"})


@app.get("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


@app.get("/api/fetch")
def fetch_url():
    target_url = request.args.get("url", "").strip()
    if not target_url:
        FETCH_REQUESTS.labels(result="bad_request").inc()
        SSRF_ATTEMPTS.labels(result="bad_request").inc()
        return jsonify({"error": "missing url"}), 400

    logging.info("Fetching URL: %s", target_url)

    try:
        with FETCH_LATENCY.time():
            response = requests.get(target_url, timeout=DEFAULT_TIMEOUT)
        FETCH_REQUESTS.labels(result="success").inc()
        SSRF_ATTEMPTS.labels(result="success").inc()
        return jsonify({
            "status": response.status_code,
            "content": response.text[:500],
        })
    except requests.RequestException as exc:
        FETCH_REQUESTS.labels(result="error").inc()
        SSRF_ATTEMPTS.labels(result="error").inc()
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=APP_PORT, debug=True)
