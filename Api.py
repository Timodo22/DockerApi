from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime, timedelta
import httpx, os, uuid, secrets, json, jwt

# -----------------------------------------------------
# INIT
# -----------------------------------------------------
app = FastAPI(title="Paradym Login Verifier API (met directe JWT generatie)")

# ⚙️ Configuration
BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"
PARADYM_API_KEY = os.getenv(
    "PARADYM_API_KEY",
    "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"
)
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")
PRESENTATION_TEMPLATE_ID = os.getenv("PARADYM_TEMPLATE_ID", "cmhowizsb00i0s601kmfkmews")

# -----------------------------------------------------
# JWT CONFIG via Render Secret Files
# -----------------------------------------------------
def read_secret_file(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception as e:
        print(f"[ERROR] Kon secret file niet lezen ({path}): {e}", flush=True)
        return None

JWT_PRIVATE_KEY = read_secret_file("/etc/secrets/ec_private.pem")
JWT_PUBLIC_KEY = read_secret_file("/etc/secrets/ec_public.pem")

JWT_ISSUER = "ParadymVerifier"
JWT_EXP_MINUTES = 15  # geldigheid van token in minuten

if not JWT_PRIVATE_KEY:
    print("[WARN] ❌ Private key niet gevonden in /etc/secrets/ec_private.pem", flush=True)
if not JWT_PUBLIC_KEY:
    print("[WARN] ❌ Public key niet gevonden in /etc/secrets/ec_public.pem", flush=True)

# -----------------------------------------------------
# MIDDLEWARE
# -----------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------
# MODELS
# -----------------------------------------------------
class PresentationRequest(BaseModel):
    issuer: str = "local"
    purpose: str = "Login"

# -----------------------------------------------------
# HELPERS
# -----------------------------------------------------
def now_iso() -> str:
    return datetime.utcnow().isoformat()

def generate_jwt(payload: dict) -> str:
    """Genereer een ES256 JWT token op basis van de private key uit /etc/secrets."""
    if not JWT_PRIVATE_KEY:
        raise RuntimeError("Private key ontbreekt. Plaats ec_private.pem als secret file in Render.")
    token = jwt.encode(payload, JWT_PRIVATE_KEY, algorithm="ES256")
    return token

# -----------------------------------------------------
# PARADYM STATUS HELPER
# -----------------------------------------------------
async def get_paradym_status(presentation_id: str) -> dict:
    url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/{presentation_id}"
    headers = {"x-access-token": PARADYM_API_KEY}

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return {"error": f"{resp.status_code}", "raw": resp.text}

    try:
        return resp.json()
    except Exception:
        return {"error": "invalid_json", "raw": resp.text}

# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------
@app.get("/")
async def root():
    return {
        "status": "running",
        "service": "Paradym Login Verifier (JWT direct generator)",
        "project_id": PROJECT_ID,
        "template_id": PRESENTATION_TEMPLATE_ID,
        "base_url": BASE_URL,
    }

# -----------------------------------------------------
# 1️⃣ Create verification request
# -----------------------------------------------------
@app.post("/request/create")
async def create_request(req: PresentationRequest):
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)

    payload = {
        "presentationTemplateId": PRESENTATION_TEMPLATE_ID,
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "state": state
    }

    headers = {"x-access-token": PARADYM_API_KEY, "Content-Type": "application/json"}
    api_url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/request"

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)

    if resp.status_code not in (200, 201):
        return JSONResponse(status_code=resp.status_code, content={"error": resp.text})

    data = resp.json()
    return {
        "request_id": request_id,
        "openid_url": data.get("authorizationRequestUri"),
        "openid_qr_url": data.get("authorizationRequestQrUri") or data.get("authorizationRequestUri"),
        "presentation_id": data.get("id"),
    }

# -----------------------------------------------------
# 2️⃣ Directe JWT generatie uit Paradym-resultaat
# -----------------------------------------------------
@app.post("/jwt/from_paradym")
async def jwt_from_paradym(request: Request):
    """Genereert een JWT direct uit de Paradym verificatie-JSON."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if body.get("status") != "verified":
        raise HTTPException(status_code=400, detail="Verification not completed")

    # Pak de relevante data uit
    try:
        cred = body["credentials"][0]
        attrs = cred.get("presentedAttributes", {})
        holder = cred.get("holder") or attrs.get("cnf", {}).get("kid", "unknown")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid credentials format: {e}")

    # Bouw JWT payload
    now = datetime.utcnow()
    payload = {
        "sub": holder,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXP_MINUTES),
        "role": attrs.get("role"),
        "gemeente": attrs.get("gemeente"),
        "vct": attrs.get("vct"),
    }

    try:
        token = generate_jwt(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"JWT generation failed: {e}")

    return {"jwt_token": token, "payload": payload}

# -----------------------------------------------------
# 3️⃣ Public key endpoint
# -----------------------------------------------------
@app.get("/.well-known/jwks.json")
async def jwks():
    if not JWT_PUBLIC_KEY:
        raise HTTPException(status_code=404, detail="Public key niet gevonden in /etc/secrets/ec_public.pem")
    return {"algorithm": "ES256", "public_key": JWT_PUBLIC_KEY, "issuer": JWT_ISSUER}

# -----------------------------------------------------
# 4️⃣ Frontend
# -----------------------------------------------------
@app.get("/frontend")
async def serve_frontend():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(path)

@app.get("/dashboard.html")
async def serve_dashboard():
    path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if not os.path.exists(path):
        return PlainTextResponse("Upload dashboard.html naast dit bestand.")
    return FileResponse(path)

# -----------------------------------------------------
# RUN LOCAL
# -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Paradym Login Verifier API (direct JWT mode) on port 8000", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=8000)
