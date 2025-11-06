from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlencode
import uuid, secrets, json, os, base64

# -----------------------------------------------------
# INIT
# -----------------------------------------------------
app = FastAPI(title="Paradym Login Verifier API")

BASE_URL = os.getenv("BASE_URL", "https://dockerapi-aika.onrender.com")
PARADYM_BASE = "https://paradym.id"

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

# ✅ Serve static definition JSON files for Paradym Wallet
app.mount("/definitions", StaticFiles(directory="definitions"), name="definitions")

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
# HELPERS
# -----------------------------------------------------
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

# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------
@app.get("/")
async def root():
    return {"status": "running", "service": "Paradym Login Verifier"}

# -----------------------------------------------------
# 1️⃣ Create presentation request
# -----------------------------------------------------
@app.post("/request/create")
async def create_request(req: PresentationRequest):
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Presentation Definition (required by Paradym)
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

    # Save definition so Paradym can fetch it
    os.makedirs("definitions", exist_ok=True)
    definition_path = f"definitions/{request_id}.json"
    with open(definition_path, "w") as f:
        json.dump(definition, f)

    sessions[request_id] = {
        "state": state,
        "status": "pending",
        "issuer": req.issuer,
        "created": datetime.utcnow().isoformat(),
    }

    presentation_definition_uri = f"{BASE_URL}/definitions/{request_id}.json"
    print(f"[DEBUG] Presentation definition URL: {presentation_definition_uri}")

    params = {
        "response_type": "vp_token",
        "client_id": f"{BASE_URL}/client",
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "response_mode": "direct_post",
        "state": state,
        "nonce": nonce,
        "presentation_definition_uri": presentation_definition_uri
    }

    # ✅ Use deep link so wallet opens directly
    openid_url = f"openid4vp://?{urlencode(params)}"

    print(f"[DEBUG] OpenID4VP link: {openid_url}")

    return {"request_id": request_id, "openid_url": openid_url}

# -----------------------------------------------------
# 2️⃣ Receive presentation from Paradym Wallet
# -----------------------------------------------------
@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Request not found")

    data = await request.json()
    print(f"[DEBUG] Received presentation for {request_id}:\n{json.dumps(data, indent=2)}")

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

    print(f"[DEBUG] ✅ Presentation completed for {holder}")
    return {"success": True}

# -----------------------------------------------------
# 3️⃣ Check presentation status
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def status(request_id: str):
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
