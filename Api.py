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
app = FastAPI(title="Paradym Login Verifier API (Official Paradym API)")

# ⚙️ Base configuration
BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://api.paradym.id"
PARADYM_API_KEY = "paradym_e230f2ddfe60f9f3b74137e538354863015a678e98336a04a099a22215cea79c"
PROJECT_ID = os.getenv("PARADYM_PROJECT_ID", "cmhnkcs29000601s6dimvb8hh")  # ⚠️ Zet hier je echte projectId

if not PARADYM_API_KEY or PROJECT_ID == "your_project_id_here":
    print("⚠️  Let op: je hebt nog geen geldige PARADYM_API_KEY of PROJECT_ID ingesteld!")

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

    # Presentation Definition (Paradym-format)
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

    # Paradym expects this payload
    payload = {
        "presentation_definition": presentation_definition,
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "state": state
    }

    headers = {
        "Authorization": f"Bearer {PARADYM_API_KEY}",
        "Content-Type": "application/json"
    }

    api_url = f"{PARADYM_BASE}/v1/projects/{PROJECT_ID}/openid4vc/verification/request"
    print(f"[DEBUG] Creating verification request via Paradym API: {api_url}")
    print(f"[DEBUG] Payload:\n{json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)

    print(f"[DEBUG] Paradym raw response status: {resp.status_code}")
    print(f"[DEBUG] Paradym raw text: {resp.text}")

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    try:
        data = resp.json()
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid JSON from Paradym API")

    verify_url = (
        data.get("verify_url")
        or data.get("url")
        or data.get("deeplink")
        or data.get("verification_url")
    )

    if not verify_url:
        raise HTTPException(status_code=500, detail=f"Paradym API did not return a verify URL: {data}")

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
