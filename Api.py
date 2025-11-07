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
    "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"  # demo key
)
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")
PRESENTATION_TEMPLATE_ID = os.getenv("PARADYM_TEMPLATE_ID", "cmho2guje00dds601ym08hk7f")

# -----------------------------------------------------
# MIDDLEWARE
# -----------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # vrij voor POC
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
            return JSONResponse(
                status_code=500,
                content={"error": "Paradym API connection failed", "details": str(e)},
            )

    if resp.status_code not in (200, 201):
        safe_print(f"[ERROR] Paradym API returned {resp.status_code}: {resp.text}")
        return JSONResponse(
            status_code=resp.status_code,
            content={"error": "Paradym API failed", "response": resp.text},
        )

    try:
        data = resp.json()
    except Exception as e:
        safe_print(f"[ERROR] Paradym response not JSON: {e}\n{resp.text}")
        return JSONResponse(
            status_code=500,
            content={"error": "Invalid JSON response from Paradym", "raw": resp.text},
        )

    link = data.get("authorizationRequestUri")
    qr_link = data.get("authorizationRequestQrUri") or link
    if not link:
        return JSONResponse(
            status_code=500,
            content={"error": "Paradym API did not return authorizationRequestUri", "raw": data},
        )

    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "verified": False,
        "created_at": now_iso(),
        "link_url": link,
        "qr_url": qr_link,
    }

    safe_print(f"[DEBUG] ✅ Created verification request {request_id}")
    safe_print(f"[DEBUG] 🔗 {link}")
    safe_print(f"[DEBUG] 🔳 {qr_link}")

    return JSONResponse(
        content={
            "request_id": request_id,
            "openid_url": link,
            "openid_qr_url": qr_link
        }
    )

# -----------------------------------------------------
# 2️⃣ Receive presentation result
# -----------------------------------------------------
@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    safe_print(f"[DEBUG] 📩 Callback received for {request_id}")

    if request_id not in sessions:
        sessions[request_id] = {"status": "pending", "created_at": now_iso()}
        safe_print(f"[WARN] Created new session for unknown request_id {request_id}")

    content_type = (request.headers.get("content-type") or "").lower()
    body = {}
    try:
        if "json" in content_type:
            body = await request.json()
        elif "form" in content_type:
            parsed = parse_qs((await request.body()).decode())
            body = {k: v[0] if isinstance(v, list) else v for k, v in parsed.items()}
        else:
            raw = (await request.body()).decode()
            try:
                body = json.loads(raw)
            except Exception:
                body = {"raw_body": raw}
    except Exception as e:
        body = {"parse_error": str(e)}

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
# 3️⃣ Check status
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
