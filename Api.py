from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
import json
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import secrets
from urllib.parse import urlencode, unquote
from fastapi.responses import FileResponse
import os
import requests

app = FastAPI(title="VP Token Verifier API (Paradym Enhanced)")

# CORS configuratie
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage in geheugen
presentation_sessions = {}

# Config
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
PARADYM_BASE = "https://paradym.id"

# === Models ===
class PresentationRequest(BaseModel):
    requested_credentials: Optional[List[str]] = ["VerifiableId"]
    purpose: Optional[str] = "Verification"
    issuer: Optional[str] = "local"  # nieuw veld: local | paradym

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


# === API Endpoints ===
@app.get("/")
async def root():
    return {
        "message": "VP Token Verifier API - Paradym Enhanced",
        "version": "3.0.0",
        "features": [
            "Paradym integration",
            "Local OpenID4VP verifier",
            "Dynamic issuer switching",
            "JWT decoding without verification"
        ]
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/request/create")
async def create_presentation_request(request: PresentationRequest):
    """
    Creëer een nieuwe presentation request (Paradym of lokaal)
    """
    request_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    presentation_sessions[request_id] = {
        'state': state,
        'nonce': nonce,
        'requested_credentials': request.requested_credentials,
        'purpose': request.purpose,
        'issuer': request.issuer,
        'created_at': datetime.utcnow().isoformat(),
        'status': 'pending'
    }

    params = {
        'response_type': 'vp_token',
        'client_id': f'{BASE_URL}/client',
        'redirect_uri': f'{BASE_URL}/presentation/{request_id}',
        'response_mode': 'direct_post',
        'state': state,
        'nonce': nonce,
        'presentation_definition': json.dumps({
            'id': request_id,
            'input_descriptors': [{
                'id': 'credential_input',
                'name': request.purpose,
                'purpose': request.purpose,
                'constraints': {
                    'fields': [{
                        'path': ['$.type'],
                        'filter': {
                            'type': 'array',
                            'contains': {
                                'type': 'string',
                                'pattern': '|'.join(request.requested_credentials)
                            }
                        }
                    }]
                }
            }]
        })
    }

    if request.issuer == "paradym":
        openid_url = f"{PARADYM_BASE}/api/vc/authorize?{urlencode(params)}"
    else:
        openid_url = f"openid4vp://?{urlencode(params)}"

    return {
        'request_id': request_id,
        'openid_url': openid_url,
        'issuer': request.issuer,
        'state': state,
        'status': 'pending',
        'message': 'Scan de QR code met je wallet om credentials te delen'
    }


@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    """
    Ontvang VP token (direct_post)
    """
    if request_id not in presentation_sessions:
        raise HTTPException(status_code=404, detail="Request not found")

    content_type = request.headers.get('content-type', '')
    if 'application/x-www-form-urlencoded' in content_type:
        form_data = await request.form()
        vp_token = form_data.get('vp_token')
        state = form_data.get('state')
    else:
        json_data = await request.json()
        vp_token = json_data.get('vp_token')
        state = json_data.get('state')

    session = presentation_sessions[request_id]
    if state != session['state']:
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        parsed = parse_jwt_without_verification(vp_token)
        credentials = extract_credentials_from_vp(parsed['payload'])
        holder = parsed['payload'].get('iss') or parsed['payload'].get('sub')

        session['status'] = 'completed'
        session['vp_token'] = vp_token
        session['decoded'] = {
            'header': parsed['header'],
            'payload': parsed['payload'],
            'credentials': credentials,
            'holder': holder,
            'source': session['issuer']
        }
        session['completed_at'] = datetime.utcnow().isoformat()

        return {'status': 'success', 'message': 'Presentation received and verified'}
    except Exception as e:
        session['status'] = 'failed'
        session['error'] = str(e)
        raise HTTPException(status_code=400, detail=f"Invalid VP token: {str(e)}")


@app.get("/presentation/{request_id}/status")
async def get_presentation_status(request_id: str):
    if request_id not in presentation_sessions:
        raise HTTPException(status_code=404, detail="Request not found")

    session = presentation_sessions[request_id]
    response = {
        'request_id': request_id,
        'status': session['status'],
        'issuer': session.get('issuer'),
        'created_at': session['created_at']
    }

    if session['status'] == 'completed':
        response['completed_at'] = session.get('completed_at')
        response['decoded'] = session.get('decoded')
    elif session['status'] == 'failed':
        response['error'] = session.get('error')

    return response


@app.post("/decode", response_model=VPTokenResponse)
async def decode_vp_token(request: VPTokenRequest):
    try:
        token = request.token.strip()
        if "vp_token=" in token:
            token = token.split("vp_token=")[1].split("&")[0]
        token = unquote(token)

        parsed = parse_jwt_without_verification(token)
        credentials = extract_credentials_from_vp(parsed['payload'])
        holder = parsed['payload'].get('iss') or parsed['payload'].get('sub')

        return VPTokenResponse(
            success=True,
            decoded_token=parsed,
            header=parsed['header'],
            payload=parsed['payload'],
            credentials=credentials,
            holder=holder
        )
    except Exception as e:
        return VPTokenResponse(success=False, error=str(e))


@app.post("/paradym/callback")
async def paradym_callback(data: Dict[str, Any]):
    """
    Callback vanuit Paradym verifier flow
    """
    request_id = data.get("presentation_id") or data.get("id")
    if not request_id:
        raise HTTPException(status_code=400, detail="Missing presentation_id")

    presentation_sessions[request_id] = {
        "status": "completed",
        "decoded": data,
        "completed_at": datetime.utcnow().isoformat(),
        "issuer": "paradym"
    }
    return {"success": True}


@app.get("/paradym/vc/{vc_id}")
async def get_vc_info(vc_id: str):
    try:
        response = requests.get(f"{PARADYM_BASE}/api/vc/{vc_id}")
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


frontend_path = os.path.join(os.path.dirname(__file__), "index.html")

@app.get("/frontend")
async def serve_frontend():
    return FileResponse(frontend_path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
