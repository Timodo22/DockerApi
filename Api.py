from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime
import httpx, os, uuid, secrets, json
from urllib.parse import parse_qs

# -----------------------------------------------------
# INIT
# -----------------------------------------------------
app = FastAPI(title="Paradym Login Verifier API (Official Paradym API)")

# ⚙️ Configuration
BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"
PARADYM_API_KEY = os.getenv(
    "PARADYM_API_KEY",
    "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"  # demo key
)
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")
PRESENTATION_TEMPLATE_ID = os.getenv("PARADYM_TEMPLATE_ID", "cmhowgmzr00hzs601pti9vpos")

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
# DATA STORE
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

# -----------------------------------------------------
# PARADYM STATUS HELPER
# -----------------------------------------------------
async def get_paradym_status(presentation_id: str) -> dict:
    """
    Haalt actuele verificatiestatus rechtstreeks op bij Paradym (correcte endpoint).
    """
    url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/{presentation_id}"
    headers = {"x-access-token": PARADYM_API_KEY}

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            safe_print(f"[WARN] Paradym status check failed ({resp.status_code}): {resp.text}")
            return {"error": f"{resp.status_code}", "raw": resp.text}

    try:
        data = resp.json()
    except Exception as e:
        safe_print(f"[ERROR] Invalid JSON from Paradym: {e}")
        return {"error": "invalid_json", "raw": resp.text}

    return data



# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------
@app.get("/")
async def root():
    return {
        "status": "running",
        "service": "Paradym Login Verifier (Official API)",
        "docs": "https://api.paradym.id/reference",
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

    headers = {
        "x-access-token": PARADYM_API_KEY,
        "Content-Type": "application/json"
    }

    api_url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/request"
    safe_print(f"[DEBUG] Requesting Paradym verification:\n{json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(api_url, headers=headers, json=payload)
        except Exception as e:
            safe_print(f"[ERROR] Paradym API connection failed: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})

    if resp.status_code not in (200, 201):
        safe_print(f"[ERROR] Paradym API returned {resp.status_code}: {resp.text}")
        return JSONResponse(status_code=resp.status_code, content={"error": resp.text})

    data = resp.json()
    link = data.get("authorizationRequestUri")
    qr_link = data.get("authorizationRequestQrUri") or link
    pres_id = data.get("id")

    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "verified": False,
        "created_at": now_iso(),
        "link_url": link,
        "qr_url": qr_link,
        "presentation_id": pres_id,  # bewaren voor latere lookup
    }

    safe_print(f"[DEBUG] ✅ Created verification request {request_id}")
    return {"request_id": request_id, "openid_url": link, "openid_qr_url": qr_link}

# -----------------------------------------------------
# 2️⃣ Receive presentation result (Paradym redirect fallback)
# -----------------------------------------------------
@app.get("/presentation/{request_id}")
async def presentation_redirect(request_id: str, request: Request):
    safe_print(f"[DEBUG] 🌐 GET Redirect received for {request_id}")
    params = dict(request.query_params)

    verified = params.get("verified", "true").lower() == "true"
    holder = params.get("holder") or params.get("subject") or "Onbekend"

    if request_id not in sessions:
        sessions[request_id] = {"status": "pending", "created_at": now_iso()}

    sessions[request_id].update({
        "status": "completed" if verified else "failed",
        "verified": verified,
        "holder": holder,
        "result": params,
        "completed_at": now_iso(),
    })

    safe_print(f"[DEBUG] ✅ Stored verification (GET) for {request_id}")
    return PlainTextResponse("✅ Verificatie voltooid, je mag dit venster sluiten.")

# -----------------------------------------------------
# 3️⃣ Check status (with Paradym API fallback)
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def get_status(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")

    sess = sessions[request_id]

    if sess.get("status") == "pending":
        # rechtstreeks status bij Paradym ophalen
        paradym_id = sess.get("presentation_id") or request_id
        result = await get_paradym_status(paradym_id)
        paradym_status = (result.get("status") or "").lower()

        if paradym_status in ("verified", "completed", "success"):
            sess.update({
                "status": "completed",
                "verified": True,
                "result": result,
                "completed_at": now_iso(),
            })
            safe_print(f"[DEBUG] ✅ Updated status from Paradym for {request_id}")

    return sess

# -----------------------------------------------------
# 4️⃣ Serve frontend
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
        return PlainTextResponse("Dashboard placeholder: upload dashboard.html naast dit bestand.")
    return FileResponse(path)

# -----------------------------------------------------
# RUN LOCAL
# -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    safe_print("🚀 Starting Paradym Login Verifier API on port 8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)





