import base64
import binascii
import os
import re
import secrets
import urllib.error
from typing import List, Literal, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from uid2_client import TokenGenerateInput, Uid2PublisherClient
from uid2_client.input_util import normalize_email_string

BASE_URL = "https://global.prod.uidapi.com"

load_dotenv()


def _required_setting(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be configured.")
    return value


API_KEY = _required_setting("UID2_API_KEY")
CLIENT_SECRET = _required_setting("UID2_CLIENT_SECRET")
API_BEARER_TOKEN = _required_setting("API_BEARER_TOKEN")

SUPPORTED_ID_TYPES = ("email", "email_hash")
MAX_IDENTIFIERS = len(SUPPORTED_ID_TYPES)  # each logical identifier at most once
MAX_EMAIL_LENGTH = 254
MAX_EMAIL_HASH_LENGTH = 64  # hex SHA-256; base64 SHA-256 is 44 chars

_HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

client = Uid2PublisherClient(BASE_URL, API_KEY, CLIENT_SECRET)

app = FastAPI(title="UID2 Token Generation API")
bearer_scheme = HTTPBearer(auto_error=False)


@app.middleware("http")
async def prevent_response_caching(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


def require_api_bearer(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> None:
    if credentials is None or not secrets.compare_digest(credentials.credentials, API_BEARER_TOKEN):
        raise StarletteHTTPException(
            status_code=401,
            detail="Missing or invalid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


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

def _email_input(value: str) -> TokenGenerateInput:
    if len(value) > MAX_EMAIL_LENGTH:
        raise invalid_request(f"email exceeds maximum length of {MAX_EMAIL_LENGTH} characters.")
    if normalize_email_string(value) is None:
        raise invalid_request("email is not a valid email address.")
    return TokenGenerateInput.from_email(value)


def _email_hash_input(value: str) -> TokenGenerateInput:
    if len(value) > MAX_EMAIL_HASH_LENGTH:
        raise invalid_request("email_hash is too long; expected a base64-encoded SHA-256 hash.")
    if _HEX_SHA256.match(value):
        # Accept hex SHA-256 and convert to the base64 form UID2 expects
        return TokenGenerateInput.from_hashed_email(base64.b64encode(bytes.fromhex(value)).decode("utf-8"))
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise invalid_request("email_hash is not valid base64.")
    if len(decoded) != 32:
        raise invalid_request("email_hash must be a base64-encoded SHA-256 hash (32 bytes).")
    return TokenGenerateInput.from_hashed_email(value)


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
        token_input = _email_input(value) if id_type == "email" else _email_hash_input(value)
        inputs.append((id_type, token_input))
    return inputs


# ---------- UID2 call (500 / 503) ----------

def generate_token(token_input: TokenGenerateInput) -> Optional[str]:
    """Returns the UID2 advertising token, or None if no token is available (e.g. opted out)."""
    try:
        response = client.generate_token(token_input)
    except urllib.error.HTTPError as e:
        if e.code == 429 or e.code >= 500:
            raise ApiError(503, "service_unavailable", "UID2 service is temporarily unavailable.")
        raise ApiError(500, "internal_error", f"UID2 service rejected the request (HTTP {e.code}).")
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        raise ApiError(503, "service_unavailable", "UID2 service is temporarily unavailable.")

    identity = response.get_identity()
    if identity is None:
        return None
    return identity.get_advertising_token()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/uid2/token",
    response_model=TokenResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request."},
        401: {"model": ErrorResponse, "description": "Missing or invalid bearer token."},
        500: {"model": ErrorResponse, "description": "Internal service error."},
        503: {"model": ErrorResponse, "description": "UID2 service is unavailable."},
    },
)
def generate_tokens(
    body: TokenRequest,
    _: None = Depends(require_api_bearer),
) -> TokenResponse:
    inputs = validate_identifiers(body.identifiers)
    # Try identifiers in the order given; return the first one that yields a token.
    for id_type, token_input in inputs:
        token = generate_token(token_input)
        if token:
            return TokenResponse(uid2_token=token, uid2_token_status="found", matched_id_type=id_type)
    return TokenResponse(uid2_token=None, uid2_token_status="not_found", matched_id_type="none")


if __name__ == "__main__":
    import os

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("DATABRICKS_APP_PORT", "8000")))
