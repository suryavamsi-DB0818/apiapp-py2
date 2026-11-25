import base64
import binascii
import hashlib
import json
import os
import re
import time
from typing import List, Literal, Optional

import requests
from requests.adapters import HTTPAdapter
from Crypto.Cipher import AES
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

BASE_URL = "https://operator-integ.uidapi.com"
TOKEN_GENERATE_ENDPOINT = f"{BASE_URL}/v2/token/generate"

load_dotenv()


def _required_setting(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be configured.")
    return value


API_KEY = _required_setting("UID2_API_KEY")
CLIENT_SECRET = base64.b64decode(_required_setting("UID2_CLIENT_SECRET"))

SUPPORTED_ID_TYPES = ("email", "email_hash")
MAX_IDENTIFIERS = len(SUPPORTED_ID_TYPES)
MAX_EMAIL_LENGTH = 254
MAX_EMAIL_HASH_LENGTH = 64

_HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

UID2_POOL_SIZE = 64
_http = requests.Session()
_http.mount("https://", HTTPAdapter(pool_connections=1, pool_maxsize=UID2_POOL_SIZE))
_http.headers.update({"Authorization": f"Bearer {API_KEY}"})

app = FastAPI(title="UID2 Token Generation API")


@app.middleware("http")
async def prevent_response_caching(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------- Error handling: every error is {"error": <code>, "message": <text>} ----------

class ApiError(Exception):
    def __init__(self, status_code: int, error: str, message: str):
        self.status_code = status_code
        self.error = error
        self.message = message


def error_response(status_code: int, error: str, message: str, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": error, "message": message}, headers=headers)


def invalid_request(message: str) -> ApiError:
    return ApiError(400, "invalid_request", message)


_STATUS_TO_ERROR = {
    400: "invalid_request",
    500: "internal_error",
    503: "service_unavailable",
}


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return error_response(exc.status_code, exc.error, exc.message)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    if errors and errors[0].get("type") == "json_invalid":
        message = "Request body is not valid JSON."
    elif errors:
        first = errors[0]
        loc = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
        message = f"{loc}: {first.get('msg')}" if loc else str(first.get("msg"))
    else:
        message = "Malformed request body."
    return error_response(400, "invalid_request", message)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = exc.status_code
    error = _STATUS_TO_ERROR.get(status, "invalid_request" if status < 500 else "internal_error")
    return error_response(status, error, str(exc.detail), getattr(exc, "headers", None))


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    return error_response(500, "internal_error", "Unexpected service failure.")


# ---------- Request / response models ----------

class Identifier(BaseModel):
    id_type: str
    id_value: str


class TokenRequest(BaseModel):
    identifiers: List[Identifier]


class TokenResponse(BaseModel):
    uid2_token: Optional[str]
    uid2_token_status: Literal["found", "not_found"]
    matched_id_type: Literal["email", "email_hash", "none"]


class ErrorResponse(BaseModel):
    error: str
    message: str


# ---------- Input validation (400) ----------

def _normalize_email(email: str) -> Optional[str]:
    pre_sb = []
    pre_sb_specialized = []
    sb = []
    ws_buffer = []

    parsing_local_part = False
    started = False
    in_extension = False

    for c_given in email:
        c = c_given.lower() if "A" <= c_given <= "Z" else c_given

        if not started:
            if c == " ":
                continue
            started = True
            parsing_local_part = True

        if parsing_local_part:
            if c == "@":
                parsing_local_part = False
            elif c in (".", "+"):
                pre_sb.append(c)
                if c == "+":
                    in_extension = True
            else:
                pre_sb.append(c)
                if not in_extension:
                    pre_sb_specialized.append(c)
        else:
            if c == "@":
                return None
            if c == " ":
                ws_buffer.append(c)
                continue
            if ws_buffer:
                sb.extend(ws_buffer)
                ws_buffer = []
            sb.append(c)

    if not sb:
        return None
    domain_part = "".join(sb)

    address_part_to_use = pre_sb_specialized if domain_part == "gmail.com" else pre_sb
    if not address_part_to_use:
        return None

    return "".join(address_part_to_use) + "@" + domain_part


def _email_input(value: str) -> dict:
    if len(value) > MAX_EMAIL_LENGTH:
        raise invalid_request(f"email exceeds maximum length of {MAX_EMAIL_LENGTH} characters.")
    normalized = _normalize_email(value)
    if normalized is None:
        raise invalid_request("email is not a valid email address.")
    email_hash = base64.b64encode(hashlib.sha256(normalized.encode("utf-8")).digest()).decode("utf-8")
    return {"email_hash": email_hash}


def _email_hash_input(value: str) -> dict:
    if len(value) > MAX_EMAIL_HASH_LENGTH:
        raise invalid_request("email_hash is too long; expected a base64-encoded SHA-256 hash.")
    if _HEX_SHA256.match(value):
        return {"email_hash": base64.b64encode(bytes.fromhex(value)).decode("utf-8")}
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise invalid_request("email_hash is not valid base64.")
    if len(decoded) != 32:
        raise invalid_request("email_hash must be a base64-encoded SHA-256 hash (32 bytes).")
    return {"email_hash": value}


def validate_identifiers(identifiers: List[Identifier]) -> List[tuple]:
    if not identifiers:
        raise invalid_request("identifiers must contain at least one email or email_hash.")
    if len(identifiers) > MAX_IDENTIFIERS:
        raise invalid_request(f"identifiers may contain at most {MAX_IDENTIFIERS} entries.")

    seen = set()
    inputs = []
    for i, identifier in enumerate(identifiers):
        id_type = identifier.id_type.strip().lower()
        value = identifier.id_value.strip()
        if id_type not in SUPPORTED_ID_TYPES:
            raise invalid_request(
                f"identifiers.{i}.id_type '{identifier.id_type}' is not supported; use 'email' or 'email_hash'."
            )
        if id_type in seen:
            raise invalid_request(f"identifiers.{i}: id_type '{id_type}' is repeated.")
        seen.add(id_type)
        if not value:
            raise invalid_request(f"identifiers.{i}.id_value must not be empty.")
        payload = _email_input(value) if id_type == "email" else _email_hash_input(value)
        inputs.append((id_type, payload))
    return inputs


def _encrypt_request(payload: dict, secret: bytes) -> bytes:
    iv = os.urandom(12)
    cipher = AES.new(secret, AES.MODE_GCM, nonce=iv)

    millisec = int(time.time() * 1000)
    nonce = os.urandom(8)

    body = millisec.to_bytes(8, "big") + nonce + json.dumps(payload).encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(body)

    envelope = b"\x01" + iv + ciphertext + tag
    return base64.b64encode(envelope)


def _decrypt_response(response_bytes: bytes, secret: bytes) -> dict:
    iv = response_bytes[:12]
    data = response_bytes[12:-16]
    tag = response_bytes[-16:]

    cipher = AES.new(secret, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt_and_verify(data, tag)

    return json.loads(decrypted[16:].decode("utf-8"))


# ---------- UID2 call (500 / 503) ----------

def generate_token(payload: dict) -> Optional[str]:
    envelope = _encrypt_request(payload, CLIENT_SECRET)

    try:
        response = _http.post(TOKEN_GENERATE_ENDPOINT, data=envelope)
    except requests.exceptions.RequestException:
        raise ApiError(503, "service_unavailable", "UID2 service is temporarily unavailable.")

    if response.status_code == 429 or response.status_code >= 500:
        raise ApiError(503, "service_unavailable", "UID2 service is temporarily unavailable.")
    if response.status_code >= 400:
        raise ApiError(500, "internal_error", f"UID2 service rejected the request (HTTP {response.status_code}).")

    response_bytes = base64.b64decode(response.content)
    body = _decrypt_response(response_bytes, CLIENT_SECRET)

    status = body.get("status")
    if status == "optout":
        return None
    if status != "success":
        raise ApiError(500, "internal_error", f"UID2 service returned unexpected status '{status}'.")
    return body["body"]["advertising_token"]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {
        "service": "UID2 Token Generation API",
        "health": "/health",
        "openapi": "/openapi.json",
    }


@app.post(
    "/uid2/token",
    response_model=TokenResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request."},
        500: {"model": ErrorResponse, "description": "Internal service error."},
        503: {"model": ErrorResponse, "description": "UID2 service is unavailable."},
    },
)
def generate_tokens(body: TokenRequest) -> TokenResponse:
    inputs = validate_identifiers(body.identifiers)
    for id_type, payload in inputs:
        token = generate_token(payload)
        if token:
            return TokenResponse(uid2_token=token, uid2_token_status="found", matched_id_type=id_type)
    return TokenResponse(uid2_token=None, uid2_token_status="not_found", matched_id_type="none")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("DATABRICKS_APP_PORT", "8000")))
