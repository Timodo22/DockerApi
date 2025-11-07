from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime
import httpx, os, uuid, secrets, json

# -----------------------------------------------------
# INIT
# -----------------------------------------------------
app = FastAPI(title="Paradym Login Verifier API (Official Paradym API)")

# ⚙️ Configuration
BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"
PARADYM_API_KEY = os.getenv(
    "PARADYM_API_KEY",
    "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"
)
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")
PRESENTATION_TEMPLATE_ID = os.getenv("PARADYM_TEMPLATE_ID", "cmho2guje00dds601ym08hk7f")

if not PARADYM_API_KEY or not PROJECT_ID or not PRESENTATION_TEMPLATE_ID:
    print("⚠️  Let op: PARADYM_API_KEY, PROJECT_ID of PRESENTATION_TEMPLATE_ID ontbreekt of is niet geldig.")

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
# MODEL
# -----------------------------------------------------
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
        "service": "Paradym Login Verifier (Official API)",
        "docs": "https://api.paradym.id/reference"
    }

# -----------------------------------------------------
# 1️⃣ Create verification request via Paradym API
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

    print(f"\n[DEBUG] Creating verification request via Paradym API: {api_url}")
    print(f"[DEBUG] Payload:\n{json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)

    print(f"[DEBUG] Paradym API response status: {resp.status_code}")
    print(f"[DEBUG] Paradym API raw text: {resp.text}\n")

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    try:
        data = resp.json()
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid JSON response from Paradym API")

    verify_url = (
        data.get("authorizationRequestQrUri")
        or data.get("authorizationRequestUri")
        or data.get("verify_url")
        or data.get("url")
    )

    if not verify_url:
        raise HTTPException(status_code=500, detail=f"Paradym API did not return a verify URL: {data}")

    sessions[request_id] = {
        "status": "pending",
        "verify_url": verify_url,
        "state": state,
        "issuer": req.issuer,
        "created_at": datetime.utcnow().isoformat(),
    }

    print(f"[DEBUG] ✅ Paradym verify link created for {request_id}")
    print(f"[DEBUG] 🔗 Verify URL (QR Link): {verify_url}\n")

    return {
        "request_id": request_id,
        "openid_url": verify_url
    }

# -----------------------------------------------------
# 2️⃣ Receive presentation result (callback from Paradym)
# -----------------------------------------------------
@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    if request_id not in sessions:
        print(f"[WARN] ⚠️ Callback ontvangen voor onbekend request_id: {request_id}")
        raise HTTPException(status_code=404, detail="Request not found")

    try:
        data = await request.json()
        print(f"[DEBUG] ✅ JSON callback ontvangen van Paradym voor {request_id}")
        print(json.dumps(data, indent=2))
    except Exception:
        raw = await request.body()
        text = raw.decode("utf-8")
        print(f"[WARN] ⚠️ Callback bevat geen JSON. Ruwe data:\n{text}")
        data = {"raw_body": text}

    holder = data.get("holder") or data.get("subject") or "Onbekend"
    verified = data.get("verified", True)

    sessions[request_id].update({
        "status": "completed" if verified else "failed",
        "holder": holder,
        "result": data,
        "completed_at": datetime.utcnow().isoformat()
    })

    print(f"[DEBUG] ✅ Verificatie succesvol opgeslagen voor {request_id}\n")
    return {"success": True, "verified": verified}

# -----------------------------------------------------
# 3️⃣ Check presentation status
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def get_status(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")
    return sessions[request_id]

# -----------------------------------------------------
# 4️⃣ Serve frontend
# -----------------------------------------------------
@app.get("/frontend")
async def serve_frontend():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Frontend file not found")
    return FileResponse(path)

# -----------------------------------------------------
# RUN LOCAL
# -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Paradym Login Verifier API on port 8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
