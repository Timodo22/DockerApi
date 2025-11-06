from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import FileResponse
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlencode
import uuid, secrets, json, os, base64

app = FastAPI(title="Paradym Login Verifier API")

BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://paradym.id"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sessions: Dict[str, Any] = {}

# -------------------- MODELLEN --------------------
class PresentationRequest(BaseModel):
    issuer: str = "local"
    purpose: str = "Login"
    requested_credentials: Optional[List[str]] = ["VerifiableId"]

# -------------------- HELPERS --------------------
def decode_base64url(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)

def parse_jwt(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    header = json.loads(decode_base64url(parts[0]))
    payload = json.loads(decode_base64url(parts[1]))
    return {"header": header, "payload": payload}

# -------------------- ROUTES --------------------
@app.get("/")
async def root():
    return {"status": "running", "service": "Paradym Login Verifier"}

@app.post("/request/create")
async def create_request(req: PresentationRequest):
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    definition = {
        "id": request_id,
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

    os.makedirs("definitions", exist_ok=True)
    with open(f"definitions/{request_id}.json", "w") as f:
        json.dump(definition, f)

    sessions[request_id] = {
        "state": state,
        "status": "pending",
        "issuer": req.issuer,
        "created": datetime.utcnow().isoformat(),
    }

    params = {
        "response_type": "vp_token",
        "client_id": f"{BASE_URL}/client",
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "response_mode": "direct_post",
        "state": state,
        "nonce": nonce,
        "presentation_definition_uri": f"{BASE_URL}/definitions/{request_id}.json"
    }

    openid_url = f"openid4vp://?{urlencode(params)}"
    return {"request_id": request_id, "openid_url": openid_url}

@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Request not found")

    data = await request.json()
    vp_token = data.get("vp_token")
    state = data.get("state")

    if state != sessions[request_id]["state"]:
        raise HTTPException(status_code=400, detail="Invalid state")

    parsed = parse_jwt(vp_token)
    payload = parsed["payload"]
    holder = payload.get("iss") or payload.get("sub")

    sessions[request_id].update({
        "status": "completed",
        "holder": holder,
        "payload": payload,
        "completed_at": datetime.utcnow().isoformat()
    })

    return {"success": True}

@app.get("/presentation/{request_id}/status")
async def status(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")
    return sessions[request_id]

@app.get("/frontend")
async def serve_frontend():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

