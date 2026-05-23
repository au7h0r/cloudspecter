import os
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock

from flask import Flask, Response, jsonify, make_response, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloudspecter-imds")

IMDS_TOKEN_HEADER = "X-aws-ec2-metadata-token"
IMDS_TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"
IMDS_PORT = int(os.getenv("IMDS_PORT", "1338"))

IMDS_REQUESTS = Counter(
    "cloudspecter_imds_requests_total",
    "Total requests handled by the IMDS emulator",
    ["endpoint", "result"],
)
METADATA_ACCESS = Counter(
    "cloudspecter_metadata_access_total",
    "Total metadata access attempts handled by the IMDS emulator",
    ["endpoint", "result"],
)
IMDS_TOKENS_ISSUED = Counter(
    "cloudspecter_imds_tokens_issued_total",
    "Total IMDSv2 tokens issued",
)
FAILED_TOKEN_REQUESTS = Counter(
    "cloudspecter_failed_token_requests_total",
    "Total failed IMDSv2 token requests",
)


@dataclass
class TokenRecord:
    token: str
    expires_at: datetime


@dataclass
class CredentialRecord:
    access_key_id: str
    secret_access_key: str
    session_token: str
    last_updated: datetime
    expiration: datetime


class ImdsState:
    def __init__(self) -> None:
        self._lock = RLock()
        self._tokens: dict[str, TokenRecord] = {}
        self._role_name = "CloudSpecterLabRole"
        self._credentials = self._build_credentials()

    def _build_credentials(self) -> CredentialRecord:
        now = datetime.now(timezone.utc)
        return CredentialRecord(
            access_key_id=f"ASIA{secrets.token_hex(8).upper()}",
            secret_access_key=secrets.token_urlsafe(30),
            session_token=secrets.token_urlsafe(64),
            last_updated=now,
            expiration=now + timedelta(hours=12),
        )

    def issue_token(self, ttl_seconds: int) -> str:
        ttl_seconds = max(1, min(ttl_seconds, 21600))
        token = secrets.token_urlsafe(48)
        record = TokenRecord(token=token, expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds))

        with self._lock:
            self._tokens[token] = record

        return token

    def validate_token(self, token: str | None) -> bool:
        if not token:
            return False

        with self._lock:
            record = self._tokens.get(token)

        return bool(record and record.expires_at > datetime.now(timezone.utc))

    @property
    def role_name(self) -> str:
        return self._role_name

    @property
    def credentials(self) -> CredentialRecord:
        now = datetime.now(timezone.utc)
        if now >= self._credentials.expiration:
            self._credentials = self._build_credentials()
        return self._credentials


state = ImdsState()


def _json_error(message: str, status_code: int):
    return jsonify({"error": message}), status_code


def _token_required() -> bool:
    return os.getenv("IMDS_REQUIRE_TOKEN", "false").lower() == "true"


def _is_token_valid() -> bool:
    token = request.headers.get(IMDS_TOKEN_HEADER)
    return state.validate_token(token)


def _guard_metadata_request():
    if _token_required() and not _is_token_valid():
        return _json_error("IMDSv2 token required", 401)
    return None


@app.get("/")
def home():
    IMDS_REQUESTS.labels(endpoint="home", result="success").inc()
    return jsonify({
        "service": "CloudSpecter IMDS Emulator",
        "version": "1.0",
        "paths": [
            "/latest/meta-data/",
            "/latest/meta-data/iam/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/api/token",
        ],
    })


@app.put("/latest/api/token")
def create_token():
    ttl_raw = request.headers.get(IMDS_TOKEN_TTL_HEADER)
    if ttl_raw is None:
        IMDS_REQUESTS.labels(endpoint="token", result="bad_request").inc()
        FAILED_TOKEN_REQUESTS.inc()
        return _json_error(f"missing {IMDS_TOKEN_TTL_HEADER}", 400)

    try:
        ttl_seconds = int(ttl_raw)
    except ValueError:
        IMDS_REQUESTS.labels(endpoint="token", result="bad_request").inc()
        FAILED_TOKEN_REQUESTS.inc()
        return _json_error("invalid ttl", 400)

    token = state.issue_token(ttl_seconds)
    IMDS_TOKENS_ISSUED.inc()
    IMDS_REQUESTS.labels(endpoint="token", result="success").inc()
    response = make_response(token, 200)
    response.headers["Content-Type"] = "text/plain"
    response.headers["x-aws-ec2-metadata-token-ttl-seconds"] = str(max(1, min(ttl_seconds, 21600)))
    return response


@app.get("/latest/meta-data")
@app.get("/latest/meta-data/")
def meta_root():
    guard = _guard_metadata_request()
    if guard:
        IMDS_REQUESTS.labels(endpoint="meta_root", result="unauthorized").inc()
        METADATA_ACCESS.labels(endpoint="meta_root", result="unauthorized").inc()
        return guard

    IMDS_REQUESTS.labels(endpoint="meta_root", result="success").inc()
    METADATA_ACCESS.labels(endpoint="meta_root", result="success").inc()
    return Response("iam/\n", mimetype="text/plain")


@app.get("/latest/meta-data/iam")
@app.get("/latest/meta-data/iam/")
def iam_root():
    guard = _guard_metadata_request()
    if guard:
        IMDS_REQUESTS.labels(endpoint="iam_root", result="unauthorized").inc()
        METADATA_ACCESS.labels(endpoint="iam_root", result="unauthorized").inc()
        return guard

    IMDS_REQUESTS.labels(endpoint="iam_root", result="success").inc()
    METADATA_ACCESS.labels(endpoint="iam_root", result="success").inc()
    return Response("security-credentials/\n", mimetype="text/plain")


@app.get("/latest/meta-data/iam/security-credentials")
@app.get("/latest/meta-data/iam/security-credentials/")
def iam_role_list():
    guard = _guard_metadata_request()
    if guard:
        IMDS_REQUESTS.labels(endpoint="role_list", result="unauthorized").inc()
        METADATA_ACCESS.labels(endpoint="role_list", result="unauthorized").inc()
        return guard

    IMDS_REQUESTS.labels(endpoint="role_list", result="success").inc()
    METADATA_ACCESS.labels(endpoint="role_list", result="success").inc()
    return Response(f"{state.role_name}\n", mimetype="text/plain")


@app.get("/latest/meta-data/iam/security-credentials/<role_name>")
def iam_credentials(role_name: str):
    guard = _guard_metadata_request()
    if guard:
        IMDS_REQUESTS.labels(endpoint="credentials", result="unauthorized").inc()
        METADATA_ACCESS.labels(endpoint="credentials", result="unauthorized").inc()
        return guard

    if role_name != state.role_name:
        IMDS_REQUESTS.labels(endpoint="credentials", result="not_found").inc()
        METADATA_ACCESS.labels(endpoint="credentials", result="not_found").inc()
        return _json_error("unknown role", 404)

    creds = state.credentials
    IMDS_REQUESTS.labels(endpoint="credentials", result="success").inc()
    METADATA_ACCESS.labels(endpoint="credentials", result="success").inc()
    payload = {
        "Code": "Success",
        "LastUpdated": creds.last_updated.isoformat().replace("+00:00", "Z"),
        "Type": "AWS-HMAC",
        "AccessKeyId": creds.access_key_id,
        "SecretAccessKey": creds.secret_access_key,
        "Token": creds.session_token,
        "Expiration": creds.expiration.isoformat().replace("+00:00", "Z"),
    }
    return jsonify(payload)


@app.get("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=IMDS_PORT, debug=True)