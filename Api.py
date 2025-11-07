from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime
import httpx, os, uuid, secrets, json, sys, traceback
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
# ROUTES
# -----------------------------------------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "Paradym Login Verifier API"}

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

    safe_print(f"\n[DEBUG] Creating verification request: {api_url}")
    safe_print(f"[DEBUG] Payload:\n{json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)

    safe_print(f"[DEBUG] Paradym response: {resp.status_code}")
    safe_print(f"[DEBUG] Raw text: {resp.text}\n")

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    data = resp.json()
    link = data.get("authorizationRequestUri")
    qr_link = data.get("authorizationRequestQrUri") or link

    if not link:
        raise HTTPException(status_code=500, detail=f"Paradym API returned no link: {data}")

    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "issuer": req.issuer,
        "created_at": now_iso(),
        "link_url": link,
        "qr_url": qr_link,
        "raw": data,
    }

    safe_print(f"[DEBUG] ✅ Created verify link for {request_id}")
    safe_print(f"[DEBUG] 🔗 {link}")

    return {"request_id": request_id, "openid_url": link, "openid_qr_url": qr_link}

# -----------------------------------------------------
# 2️⃣ Receive presentation result
# -----------------------------------------------------
@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    safe_print(f"[DEBUG] 📩 Callback from Paradym: {request_id}")

    if request_id not in sessions:
        sessions[request_id] = {"status": "pending", "created_at": now_iso()}

    content_type = request.headers.get("content-type", "")
    body = {}
    try:
        if "json" in content_type:
            body = await request.json()
        elif "form" in content_type:
            parsed = parse_qs((await request.body()).decode())
            body = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in parsed.items()}
        else:
            raw = (await request.body()).decode()
            try:
                body = json.loads(raw)
            except Exception:
                body = {"raw": raw}
    except Exception as e:
        body = {"error": str(e)}

    verified = bool(body.get("verified", True))
    holder = body.get("holder") or body.get("subject") or "Onbekend"

    sessions[request_id].update({
        "status": "completed" if verified else "failed",
        "verified": verified,
        "holder": holder,
        "result": body,
        "completed_at": now_iso(),
    })

    safe_print(f"[DEBUG] ✅ Stored verification for {request_id}")
    return JSONResponse({"success": True, "verified": verified})

# -----------------------------------------------------
# 3️⃣ Status
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def get_status(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")
    return sessions[request_id]

# -----------------------------------------------------
# 4️⃣ Frontend
# -----------------------------------------------------
@app.get("/frontend")
async def serve_frontend():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Frontend file not found")
    return FileResponse(path)

# -----------------------------------------------------
# RUN
# -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    safe_print("🚀 Starting Paradym Login Verifier API on port 8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
