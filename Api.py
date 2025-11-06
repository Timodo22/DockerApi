from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import FileResponse
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlencode, unquote
import uuid, secrets, json, os, base64, requests

app = FastAPI(title="VP Token Verifier API (Paradym Enhanced)")

# === Config ===
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
PARADYM_BASE = "https://paradym.id"

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Storage in geheugen ===
presentation_sessions: Dict[str, Any] = {}

# === Models ===
class PresentationRequest(BaseModel):
    requested_credentials: Optional[List[str]] = ["VerifiableId"]
    purpose: Optional[str] = "Verification"
    issuer: Optional[str] = "local"  # 'local' | 'paradym'

class VPTokenRequest(BaseModel):
    token: str
    verify_signature: bool = False

class VPTokenResponse(BaseModel):
    success: bool
    decoded_token: Optional[Dict[str, Any]] = None
    header: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    credentials: Optional[list] = None
    holder: Optional[str] = None
    error: Optional[str] = None


# === Helpers ===
def decode_base64url(data: str) -> bytes:
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)

def parse_jwt_without_verification(token: str) -> Dict[str, Any]:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = json.loads(decode_base64url(parts[0]))
    payload = json.loads(decode_base64url(parts[1]))
    return {'header': header, 'payload': payload, 'signature': parts[2]}

def extract_credentials_from_vp(payload: Dict[str, Any]) -> list:
    credentials = []
    if 'vp' in payload:
        vp = payload['vp']
        if 'verifiableCredential' in vp:
            vcs = vp['verifiableCredential']
            if isinstance(vcs, list):
                for vc in vcs:
                    if isinstance(vc, str):
                        try:
                            decoded_vc = parse_jwt_without_verification(vc)
                            credentials.append({
                                'type': 'jwt',
                                'header': decoded_vc['header'],
                                'payload': decoded_vc['payload']
                            })
                        except:
                            credentials.append({'type': 'string', 'value': vc})
                    else:
                        credentials.append({'type': 'object', 'data': vc})
    return credentials


# === Routes ===

@app.get("/")
async def root():
    return {"message": "Paradym VP Token Verifier API", "status": "running", "base_url": BASE_URL}


@app.post("/request/create")
async def create_presentation_request(request: PresentationRequest):
    """Creëer een nieuwe presentation request (Paradym of lokaal)"""
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Presentation Definition
    definition = {
        "id": request_id,
        "input_descriptors": [{
            "id": "credential_input",
            "name": request.purpose,
            "purpose": request.purpose,
            "constraints": {
                "fields": [{
                    "path": ["$.type"],
                    "filter": {
                        "type": "array",
                        "contains": {
                            "type": "string",
                            "pattern": "|".join(request.requested_credentials)
                        }
                    }
                }]
            }
        }]
    }

    # Sla op als JSON-bestand zodat wallets presentation_definition_uri kunnen gebruiken
    os.makedirs("definitions", exist_ok=True)
    definition_path = f"definitions/{request_id}.json"
    with open(definition_path, "w") as f:
        json.dump(definition, f)

    presentation_sessions[request_id] = {
        "state": state,
        "nonce": nonce,
        "issuer": request.issuer,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
    }

    params = {
        "response_type": "vp_token",
        "client_id": f"{BASE_URL}/client",
        "redirect_uri": f"{BASE_URL}/presentation/{request_id}",
        "response_mode": "direct_post",
        "state": state,
        "nonce": nonce,
        "presentation_definition_uri": f"{BASE_URL}/{definition_path}"
    }

    if request.issuer == "paradym":
        openid_url = f"{PARADYM_BASE}/api/vc/authorize?{urlencode(params)}"
    else:
        openid_url = f"openid4vp://?{urlencode(params)}"

    return {
        "request_id": request_id,
        "openid_url": openid_url,
        "issuer": request.issuer,
        "state": state,
        "message": "Scan de QR code met je wallet om credentials te delen"
    }


@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    """Ontvang VP token (direct_post)"""
    if request_id not in presentation_sessions:
        raise HTTPException(status_code=404, detail="Request not found")

    data = await request.json()
    vp_token = data.get("vp_token")
    state = data.get("state")
    session = presentation_sessions[request_id]

    if state != session["state"]:
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        parsed = parse_jwt_without_verification(vp_token)
        credentials = extract_credentials_from_vp(parsed["payload"])
        holder = parsed["payload"].get("iss") or parsed["payload"].get("sub")

        session.update({
            "status": "completed",
            "vp_token": vp_token,
            "decoded": {
                "header": parsed["header"],
                "payload": parsed["payload"],
                "credentials": credentials,
                "holder": holder
            },
            "completed_at": datetime.utcnow().isoformat()
        })
        return {"status": "success", "message": "Presentation received"}
    except Exception as e:
        session["status"] = "failed"
        session["error"] = str(e)
        raise HTTPException(status_code=400, detail=f"Invalid VP token: {e}")


@app.post("/paradym/callback")
async def paradym_callback(data: Dict[str, Any]):
    """Callback vanuit Paradym verifier flow"""
    request_id = data.get("presentation_id") or data.get("id")
    if not request_id:
        raise HTTPException(status_code=400, detail="Missing presentation_id")
    presentation_sessions[request_id] = {
        "status": "completed",
        "decoded": data,
        "issuer": "paradym",
        "completed_at": datetime.utcnow().isoformat(),
    }
    return {"success": True}


@app.get("/presentation/{request_id}/status")
async def get_presentation_status(request_id: str):
    if request_id not in presentation_sessions:
        raise HTTPException(status_code=404, detail="Request not found")
    return presentation_sessions[request_id]


@app.get("/frontend")
async def serve_frontend():
    """Serve the demo HTML UI"""
    frontend_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(frontend_path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
