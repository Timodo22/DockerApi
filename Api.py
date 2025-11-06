from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime
import httpx, os, uuid, secrets, json

# -----------------------------------------------------
# INIT
# -----------------------------------------------------
app = FastAPI(title="Paradym Login Verifier API (official Paradym API)")

# ⚙️ Base URLs
BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"   # ✅ juiste endpoint
PARADYM_API_KEY = "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"

if not PARADYM_API_KEY:
    print("⚠️  Warning: PARADYM_API_KEY is not set. Add it to your environment variables.")

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
# MODELLEN
# -----------------------------------------------------
class PresentationRequest(BaseModel):
    issuer: str = "local"
    purpose: str = "Login"
    requested_credentials: Optional[List[str]] = ["VerifiableId"]

# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------
@app.get("/")
async def root():
    return {"status": "running", "service": "Paradym Login Verifier (official API)"}

# -----------------------------------------------------
# 1️⃣ Create verification request via Paradym API
# -----------------------------------------------------
@app.post("/request/create")
async def create_request(req: PresentationRequest):
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)

    # Presentation definition structure (required by Paradym)
    presentation_definition = {
        "id": request_id,
        "format": {"jwt_vp": {"alg": ["ES256", "EdDSA"]}},
        "input_descriptors": [{
            "id": "login_credential",
            "name": req.purpose,
            "purpose": req.purpose,
            "constraints": {
                "fields": [{
                    "path": ["$.type"],
                    "filter": {
                        "type": "array",
                        "contains": {
                            "type": "string",
                            "pattern": "|".join(req.requested_credentials)
                        }
                    }
                }]
            }
        }]
    }

    payload = {
        "presentation_definition": presentation_definition,
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "state": state
    }

    headers = {
        "Authorization": f"Bearer {PARADYM_API_KEY}",
        "Content-Type": "application/json"
    }

    print(f"[DEBUG] Creating verification request via Paradym API at {PARADYM_BASE}/api/verify ...")
    print(f"[DEBUG] Payload:\n{json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{PARADYM_BASE}/api/verify", headers=headers, json=payload)

    print(f"[DEBUG] Paradym raw response status: {resp.status_code}")
    print(f"[DEBUG] Paradym raw text: {resp.text}")

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    try:
        data = resp.json()
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid JSON from Paradym API")

    verify_url = data.get("verify_url") or data.get("url") or data.get("deeplink")

    if not verify_url:
        raise HTTPException(status_code=500, detail=f"Paradym API did not return verify_url. Response: {data}")

    # Store session
    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "issuer": req.issuer,
        "created": datetime.utcnow().isoformat(),
        "verify_url": verify_url
    }

    print(f"[DEBUG] ✅ Paradym verify link created for {request_id}")
    print(f"[DEBUG] Open link (QR): {verify_url}")

    return {"request_id": request_id, "openid_url": verify_url}

# -----------------------------------------------------
# 2️⃣ Receive presentation result (callback from Paradym)
# -----------------------------------------------------
@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Request not found")

    data = await request.json()
    print(f"[DEBUG] ✅ Received callback from Paradym for {request_id}")
    print(json.dumps(data, indent=2))

    holder = data.get("holder")
    verified = data.get("verified", False)

    sessions[request_id].update({
        "status": "completed" if verified else "failed",
        "holder": holder,
        "result": data,
        "completed_at": datetime.utcnow().isoformat()
    })

    return {"success": True, "verified": verified}

# -----------------------------------------------------
# 3️⃣ Check session status
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def get_status(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")
    return sessions[request_id]

# -----------------------------------------------------
# 4️⃣ Serve frontend (optional)
# -----------------------------------------------------
@app.get("/frontend")
async def serve_frontend():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(path)

# -----------------------------------------------------
# RUN LOCAL
# -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
