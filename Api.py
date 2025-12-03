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
app = FastAPI(title="Paradym Login Verifier API (met automatische JWT)")

# ⚙️ Configuration
BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"
PARADYM_API_KEY = os.getenv(
    "PARADYM_API_KEY",
    "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"
)
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")
PRESENTATION_TEMPLATE_ID = os.getenv("PARADYM_TEMPLATE_ID", "cmi2yvv8c009is601pojhv310")

# -----------------------------------------------------
# JWT CONFIG
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
JWT_EXP_MINUTES = 100

if not JWT_PRIVATE_KEY:
    print("[WARN] ❌ Private key niet gevonden")
if not JWT_PUBLIC_KEY:
    print("[WARN] ❌ Public key niet gevonden")

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
# DATA STORE (in-memory)
# -----------------------------------------------------
sessions: Dict[str, Any] = {}

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

def safe_print(msg: str):
    try:
        print(msg, flush=True)
    except Exception:
        pass

def generate_jwt(holder: str, attrs: dict = None) -> str:
    """Genereer JWT met ES256."""
    if not JWT_PRIVATE_KEY:
        raise RuntimeError("Private key ontbreekt")

    now = datetime.utcnow()
    payload = {
        "sub": holder,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXP_MINUTES)
    }
    if attrs:
        payload.update(attrs)

    token = jwt.encode(payload, JWT_PRIVATE_KEY, algorithm="ES256")
    return token

async def get_paradym_status(presentation_id: str) -> dict:
    """Haal status bij Paradym."""
    url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/{presentation_id}"
    headers = {"x-access-token": PARADYM_API_KEY}

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            safe_print(f"[WARN] Paradym API {resp.status_code}: {resp.text}")
            return {"error": str(resp.status_code), "raw": resp.text}
        try:
            return resp.json()
        except Exception as e:
            safe_print(f"[ERROR] Invalid JSON: {e}")
            return {"error": "invalid_json"}

# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------
@app.get("/")
async def root():
    return {
        "status": "running",
        "service": "Paradym Login Verifier API",
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

    safe_print(f"[DEBUG] ✅ Created verification request {request_id}")
    return {
        "request_id": request_id,
        "openid_url": data.get("authorizationRequestUri"),
        "openid_qr_url": data.get("authorizationRequestQrUri"),
        "presentation_id": pres_id,
    }

# -----------------------------------------------------
# 2️⃣ Handle Paradym redirect
# -----------------------------------------------------
@app.get("/presentation/{request_id}")
async def presentation_redirect(request_id: str, request: Request):
    params = dict(request.query_params)
    verified = params.get("verified", "true").lower() == "true"
    holder = params.get("holder") or params.get("subject") or "unknown"

    sessions[request_id] = {
        "status": "completed" if verified else "failed",
        "verified": verified,
        "holder": holder,
        "params": params,
        "completed_at": now_iso(),
    }

    return PlainTextResponse("✅ Verificatie voltooid. Je mag dit venster sluiten.")

# -----------------------------------------------------
# 3️⃣ Check status + auto-JWT
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def get_status(request_id: str):
    sess = sessions.get(request_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Not found")

    # Update status vanuit Paradym
    if sess.get("status") == "pending":
        result = await get_paradym_status(sess["presentation_id"])
        if (result.get("status") or "").lower() == "verified":
            cred = result["credentials"][0]
            attrs = cred.get("presentedAttributes", {})
            holder = cred.get("holder") or attrs.get("cnf", {}).get("kid", "unknown")
            sess.update({
                "status": "completed",
                "verified": True,
                "result": result,
                "holder": holder,
                "completed_at": now_iso()
            })
            jwt_token = generate_jwt(holder, {"role": attrs.get("role"), "gemeente": attrs.get("gemeente")})
            sess["jwt_token"] = jwt_token
            safe_print(f"[DEBUG] ✅ JWT generated for {request_id}")

    if sess.get("verified") and "jwt_token" not in sess:
        # nog geen token? maak alsnog
        result = sess.get("result", {})
        cred = result.get("credentials", [{}])[0]
        attrs = cred.get("presentedAttributes", {})
        holder = sess.get("holder", "unknown")
        sess["jwt_token"] = generate_jwt(holder, {"role": attrs.get("role"), "gemeente": attrs.get("gemeente")})

    return sess

# -----------------------------------------------------
# 4️⃣ Public key endpoint
# -----------------------------------------------------
@app.get("/.well-known/jwks.json")
async def jwks():
    if not JWT_PUBLIC_KEY:
        raise HTTPException(status_code=404, detail="Public key niet gevonden")
    return {"algorithm": "ES256", "public_key": JWT_PUBLIC_KEY, "issuer": JWT_ISSUER}

# -----------------------------------------------------
# 5️⃣ Frontend bestanden
# -----------------------------------------------------
@app.get("/frontend")
async def serve_frontend():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path):
        return PlainTextResponse("Frontend niet gevonden.")
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
    safe_print("🚀 Starting Paradym Login Verifier API (auto-JWT mode) on port 8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
