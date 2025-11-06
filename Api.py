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
app = FastAPI(title="Paradym Login Verifier API (via official API)")

BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://paradym.id"
PARADYM_API_KEY = os.getenv("PARADYM_API_KEY")

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
    return {
        "status": "running",
        "service": "Paradym Login Verifier (via official API)"
    }

# -----------------------------------------------------
# 1️⃣ Create verification request (via Paradym API)
# -----------------------------------------------------
@app.post("/request/create")
async def create_request(req: PresentationRequest):
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)

    # Construct presentation definition (same format as docs)
    presentation_definition = {
        "id": request_id,
        "format": {
            "jwt_vp": {"alg": ["ES256", "EdDSA"]}
        },
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

    print("[DEBUG] Creating verification request via Paradym API...")
    print(f"[DEBUG] Payload: {json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(f"{PARADYM_BASE}/api/verify", headers=headers, json=payload)

    if resp.status_code != 200:
        print(f"[ERROR] Paradym API response: {resp.text}")
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    data = resp.json()
    verify_url = data.get("verify_url")

    if not verify_url:
        raise HTTPException(status_code=500, detail="Missing verify_url from Paradym response")

    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "issuer": req.issuer,
        "created": datetime.utcnow().isoformat(),
        "verify_url": verify_url
    }

    print(f"[DEBUG] ✅ Paradym verify link created for {request_id}")
    print(f"[DEBUG] Open link (or QR): {verify_url}")

    return {"request_id": request_id, "openid_url": verify_url}

# -----------------------------------------------------
# 2️⃣ Receive presentation result (Paradym callback)
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
# 4️⃣ Serve simple frontend (optional)
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
