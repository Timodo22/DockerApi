# Api.py — Microsoft Entra Verified ID (OpenID4VP) Verifier API
#
# Endpoints:
#   GET  /                               -> health/info
#   POST /presentation/request           -> maak QR/presentation request (geeft openid_url terug)
#   POST /presentation/callback          -> ontvangt direct_post met vp_token na scannen
#   GET  /presentation/{request_id}/status -> frontend kan status poll'en
#
# Vereist: fastapi, uvicorn, python-jose (optioneel voor claims lezen)
#   pip install fastapi uvicorn python-multipart python-jose
#
# Start lokaal:
#   uvicorn Api:app --host 0.0.0.0 --port 8000
#
# Deploy: je hebt 'm al draaien op Render (https://dockerapi-aika.onrender.com)

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional
import uuid
import json
import base64
from datetime import datetime, timezone

try:
    # Alleen gebruikt om claims on-verified te lezen (geen netwerk nodig)
    from jose import jwt
    JOSE_AVAILABLE = True
except Exception:
    JOSE_AVAILABLE = False

app = FastAPI(title="Verified ID Verifier API")

# -----------------------------
# CORS: jouw frontend + API
# -----------------------------
ALLOWED_ORIGINS = [
    "https://datastor.pages.dev",             # jouw frontend
    "https://dockerapi-aika.onrender.com",    # je API zelf (optioneel)
    "http://localhost:5173",                  # lokaal testen (optioneel)
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Entra Verified ID configuratie
# Vul deze 2 in vanuit je app-registratie
# -----------------------------
AZURE_CLIENT_ID = "780eaf2e-e0a9-421f-8ec3-006c13b504d0"
AZURE_TENANT_ID = "39d28fd2-8cad-4518-b104-f0d193a7d451"
AZURE_REDIRECT_URI = "https://dockerapi-aika.onrender.com/presentation/callback"


# -----------------------------
# In-memory sessie opslag
# In productie -> redis/db
# -----------------------------
class Session(BaseModel):
    request_id: str
    state_b64: str
    nonce: str
    created_at: str
    status: str = "waiting"         # waiting | verified | error
    vp_token: Optional[str] = None
    subject: Optional[str] = None   # extracted sub / did (indien beschikbaar)
    raw_callback: Optional[dict] = None
    error: Optional[str] = None

SESSIONS: Dict[str, Session] = {}

# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def b64url_json(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

def read_jwt_unverified(token: str) -> dict:
    """
    Alleen om claims te tonen in status (NIET als security check).
    Voor echte validatie moet je de vp_token cryptografisch verifiëren
    t.o.v. de juiste issuer/wallet keys.
    """
    if not JOSE_AVAILABLE:
        # fallback: brute split zonder verificatie (alleen payload)
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload_b64 = parts[1] + "==="
            payload_bytes = base64.urlsafe_b64decode(payload_b64.encode())
            return json.loads(payload_bytes.decode())
        except Exception:
            return {}
    try:
        return jwt.get_unverified_claims(token)
    except Exception:
        return {}

# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def root():
    return {
        "ok": True,
        "service": "Verified ID Verifier API",
        "redirect_uri": AZURE_REDIRECT_URI,
        "cors_origins": ALLOWED_ORIGINS,
        "time": now_iso(),
        "mode": "OpenID4VP (vp_token via direct_post)"
    }

@app.post("/presentation/request")
async def create_presentation_request(request: Request):
    """
    Maakt een OpenID4VP authorize URL (voor QR) met response_mode=direct_post.
    Je frontend toont deze URL als QR-code; Microsoft Authenticator kan 'm scannen.
    """
    try:
        _ = await request.body()  # niet gebruikt, maar laten staan voor uitbreidingen
    except Exception:
        pass

    request_id = str(uuid.uuid4())
    nonce = str(uuid.uuid4())

    # Stop request_id + timestamp in state zodat we in callback weten welke sessie dit is.
    state_payload = {"rid": request_id, "ts": now_iso()}
    state_b64 = b64url_json(state_payload)

    # OpenID4VP authorize URL richting Microsoft (tenant-specifiek)
    openid_url = (
        f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/authorize?"
        f"client_id={AZURE_CLIENT_ID}"
        f"&response_type=vp_token"
        f"&redirect_uri={AZURE_REDIRECT_URI}"
        f"&response_mode=direct_post"
        f"&scope=openid"
        f"&state={state_b64}"
        f"&nonce={nonce}"
    )

    session = Session(
        request_id=request_id,
        state_b64=state_b64,
        nonce=nonce,
        created_at=now_iso(),
        status="waiting"
    )
    SESSIONS[request_id] = session

    # Frontend kan 'openid_url' omzetten naar QR
    return {
        "request_id": request_id,
        "openid_url": openid_url,
        "state": state_b64,
        "nonce": nonce,
        "created_at": session.created_at,
    }

@app.post("/presentation/callback")
async def presentation_callback(request: Request):
    """
    Microsoft (of de wallet) POST deze callback met response_mode=direct_post.
    Verwacht onder meer:
      - vp_token (JWT met de verifiable presentation)
      - state   (onze base64-encoded JSON met rid)
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON in callback")

    state_b64 = data.get("state")
    vp_token = data.get("vp_token")
    error = data.get("error")

    # Vind de sessie terug via state.rid
    rid = None
    try:
        # correct padding toevoegen
        pad = "=" * ((4 - len(state_b64) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode((state_b64 + pad).encode()).decode())
        rid = decoded.get("rid")
    except Exception:
        pass

    if not rid or rid not in SESSIONS:
        # fallback: probeer op request_id die mogelijk meegestuurd is
        rid = data.get("request_id")
        if not rid or rid not in SESSIONS:
            raise HTTPException(status_code=400, detail="Unknown or expired state/request")

    session = SESSIONS[rid]
    session.raw_callback = data

    if error:
        session.status = "error"
        session.error = str(error)
        return {"ok": False, "request_id": rid, "status": "error"}

    if not vp_token:
        session.status = "error"
        session.error = "Missing vp_token"
        return {"ok": False, "request_id": rid, "status": "error"}

    # (Optioneel) lees on-verified claims voor debugging/UX
    claims = read_jwt_unverified(vp_token)
    subject = claims.get("sub") or claims.get("subject") or claims.get("cnf", {}).get("kid")

    session.vp_token = vp_token
    session.subject = subject
    session.status = "verified"

    return {"ok": True, "request_id": rid, "status": "verified"}

@app.get("/presentation/{request_id}/status")
def presentation_status(request_id: str):
    """
    Frontend pollt dit endpoint om te weten of de presentatie is afgerond.
    """
    session = SESSIONS.get(request_id)
    if not session:
        raise HTTPException(status_code=404, detail="Request not found or expired")

    response = {
        "request_id": session.request_id,
        "status": session.status,
        "created_at": session.created_at,
    }

    if session.status == "verified":
        # Let op: dit zijn on-verified claims (alleen ter illustratie/UX)
        response.update({
            "subject": session.subject,
            "has_vp_token": bool(session.vp_token),
        })
    if session.status == "error":
        response["error"] = session.error

    return response

@app.get("/health")
def health():
    return {"ok": True, "time": now_iso()}
