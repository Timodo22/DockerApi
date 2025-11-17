from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime, timedelta
import httpx, os, uuid, secrets, json, jwt
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# -----------------------------------------------------
# INIT
# -----------------------------------------------------
app = FastAPI(title="Paradym Login Verifier API (met automatische JWT + JWKS)")

BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"
PARADYM_API_KEY = os.getenv(
    "PARADYM_API_KEY",
    "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"
)
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")
PRESENTATION_TEMPLATE_ID = os.getenv("PARADYM_TEMPLATE_ID", "cmi2yvv8c009is601pojhv310")

# -----------------------------------------------------
# JWT KEYS
# -----------------------------------------------------
def read_secret_file(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except:
        return None

JWT_PRIVATE_KEY = read_secret_file("/etc/secrets/ec_private.pem")
JWT_PUBLIC_KEY_PEM = read_secret_file("/etc/secrets/ec_public.pem")

JWT_ISSUER = "ParadymVerifier"
JWT_EXP_MINUTES = 15


def load_public_jwk_components(pem_str):
    """Converteert PEM naar JWK (x,y) voor ES256."""
    key = serialization.load_pem_public_key(
        pem_str.encode(), backend=default_backend()
    )
    numbers = key.public_numbers()

    x = base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).rstrip(b"=").decode()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "kid": "paradym-key",
        "x": x,
        "y": y
    }
    return jwk


# -----------------------------------------------------
# HELPERS
# -----------------------------------------------------
def now_iso() -> str:
    return datetime.utcnow().isoformat()

def generate_jwt(holder: str, attrs: dict = None) -> str:
    if not JWT_PRIVATE_KEY:
        raise RuntimeError("Private key ontbreekt")

    now = datetime.utcnow()
    payload = {
        "sub": holder,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXP_MINUTES),
    }
    if attrs:
        payload.update(attrs)

    token = jwt.encode(payload, JWT_PRIVATE_KEY, algorithm="ES256")
    return token

async def get_paradym_status(presentation_id: str) -> dict:
    url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/{presentation_id}"
    headers = {"x-access-token": PARADYM_API_KEY}

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return {"error": str(resp.status_code), "raw": resp.text}

        return resp.json()


# -----------------------------------------------------
# MEMORY STORE
# -----------------------------------------------------
sessions: Dict[str, Any] = {}

class PresentationRequest(BaseModel):
    issuer: str = "local"
    purpose: str = "Login"


# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------

@app.get("/")
async def root():
    return {
        "status": "running",
        "jwks": f"{BASE_URL}/.well-known/jwks.json",
        "oidc": f"{BASE_URL}/.well-known/openid-configuration"
    }

# 1. Create verification request
@app.post("/request/create")
async def create_request(req: PresentationRequest):
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)

    payload = {
        "presentationTemplateId": PRESENTATION_TEMPLATE_ID,
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "state": state,
    }

    headers = {"x-access-token": PARADYM_API_KEY, "Content-Type": "application/json"}
    api_url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/request"

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)

    if resp.status_code not in (200, 201):
        return JSONResponse(status_code=resp.status_code, content={"error": resp.text})

    data = resp.json()
    pres_id = data.get("id")

    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "presentation_id": pres_id,
        "verified": False,
        "created_at": now_iso(),
    }

    return {
        "request_id": request_id,
        "openid_url": data.get("authorizationRequestUri"),
        "openid_qr_url": data.get("authorizationRequestQrUri"),
        "presentation_id": pres_id,
    }

# 2. Redirect handler
@app.get("/presentation/{request_id}")
async def presentation_redirect(request_id: str, request: Request):
    params = dict(request.query_params)
    verified = params.get("verified", "true").lower() == "true"
    user = params.get("holder") or params.get("subject") or "unknown"

    sessions[request_id] = {
        "status": "completed" if verified else "failed",
        "verified": verified,
        "holder": user,
        "params": params,
        "completed_at": now_iso(),
    }

    return PlainTextResponse("✔️ Verificatie voltooid. Je mag dit venster sluiten.")

# 3. Polling endpoint
@app.get("/presentation/{request_id}/status")
async def status(request_id: str):
    sess = sessions.get(request_id)
    if not sess:
        raise HTTPException(404)

    if sess["status"] == "pending":
        result = await get_paradym_status(sess["presentation_id"])

        if (result.get("status") or "").lower() == "verified":
            cred = result["credentials"][0]
            attrs = cred.get("presentedAttributes", {})

            holder = cred.get("holder")

            jwt_token = generate_jwt(
                holder,
                {
                    "role": attrs.get("role"),
                    "gemeente": attrs.get("gemeente")
                }
            )
            sess.update({
                "status": "completed",
                "verified": True,
                "result": result,
                "jwt_token": jwt_token
            })

    return sess

# -----------------------------------------------------
# 4. NEW: Correct JWKS endpoint (public!)
# -----------------------------------------------------
@app.get("/.well-known/jwks.json")
async def jwks():
    if not JWT_PUBLIC_KEY_PEM:
        raise HTTPException(404, "Public key niet gevonden")
    jwk = load_public_jwk_components(JWT_PUBLIC_KEY_PEM)
    return {"keys": [jwk]}

# -----------------------------------------------------
# 5. NEW: Correct OpenID Connect config
# -----------------------------------------------------
@app.get("/.well-known/openid-configuration")
async def oidc():
    return {
        "issuer": JWT_ISSUER,
        "jwks_uri": f"{BASE_URL}/.well-known/jwks.json"
    }

