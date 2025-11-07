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

if not PARADYM_API_KEY or not PROJECT_ID or not PRESENTATION_TEMPLATE_ID:
    print("⚠️  Let op: PARADYM_API_KEY, PROJECT_ID of PRESENTATION_TEMPLATE_ID ontbreekt of is niet geldig.")

# -----------------------------------------------------
# MIDDLEWARE
# -----------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # voor POC vrijgeven
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

    safe_print(f"\n[DEBUG] Creating verification request via Paradym API: {api_url}")
    safe_print(f"[DEBUG] Payload:\n{json.dumps(payload, indent=2)}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)

    safe_print(f"[DEBUG] Paradym API response status: {resp.status_code}")
    safe_print(f"[DEBUG] Paradym API raw text: {resp.text}\n")

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    try:
        data = resp.json()
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid JSON response from Paradym API")

    # Geef BEIDE varianten terug
    authorization_link = data.get("authorizationRequestUri") or data.get("verify_url") or data.get("url")
    qr_link = data.get("authorizationRequestQrUri") or authorization_link

    if not authorization_link:
        raise HTTPException(status_code=500, detail=f"Paradym API did not return an authorizationRequestUri: {data}")

    # Bewaar sessie
    sessions[request_id] = {
        "status": "pending",
        "state": state,
        "issuer": req.issuer,
        "created_at": now_iso(),
        "link_url": authorization_link,
        "qr_url": qr_link,
        "raw_paradym": data
    }

    safe_print(f"[DEBUG] ✅ Paradym verify link created for {request_id}")
    safe_print(f"[DEBUG] 🔗 Link URL: {authorization_link}")
    safe_print(f"[DEBUG] 🔳 QR URL:   {qr_link}\n")

    # Laat frontend zelf kiezen wat te gebruiken
    return {
        "request_id": request_id,
        "openid_url": authorization_link,   # voor klikken/dieplink
        "openid_qr_url": qr_link            # voor QR renderen (bevat vaak &qr=true)
    }

# -----------------------------------------------------
# 2️⃣ Receive presentation result (callback from Paradym)
# -----------------------------------------------------
@app.post("/presentation/{request_id}")
async def receive_presentation(request_id: str, request: Request):
    safe_print(f"[DEBUG] 📩 Callback ontvangen van Paradym voor request_id: {request_id}")

    # Sessie aanmaken als die ontbreekt (bijv. na container restart)
    if request_id not in sessions:
        safe_print(f"[WARN] ⚠️ Onbekend request_id {request_id}, nieuwe sessie aangemaakt.")
        sessions[request_id] = {
            "status": "pending",
            "created_at": now_iso(),
            "link_url": None,
            "qr_url": None,
        }

    # Debug: headers + query
    try:
        headers_dump = {k: v for k, v in request.headers.items()}
        safe_print(f"[DEBUG] Headers: {json.dumps(headers_dump, indent=2)}")
        safe_print(f"[DEBUG] Query:   {dict(request.query_params)}")
    except Exception:
        pass

    # Probeer JSON → x-www-form-urlencoded → raw tekst
    body_dict: Dict[str, Any] = {}
    body_text: Optional[str] = None
    content_type = request.headers.get("content-type", "")

    try:
        if "application/json" in content_type:
            body_dict = await request.json()
            safe_print(f"[DEBUG] ✅ JSON body ontvangen:\n{json.dumps(body_dict, indent=2)}")
        elif "application/x-www-form-urlencoded" in content_type:
            raw = await request.body()
            body_text = raw.decode("utf-8", errors="ignore")
            parsed = parse_qs(body_text)
            # parse_qs geeft lists; zet om naar single value indien lijst van lengte 1
            body_dict = {k: (v[0] if isinstance(v, list) and len(v) == 1 else v) for k, v in parsed.items()}
            safe_print(f"[DEBUG] ✅ URL-ENCODED body ontvangen:\n{json.dumps(body_dict, indent=2)}")
        else:
            raw = await request.body()
            body_text = raw.decode("utf-8", errors="ignore")
            safe_print(f"[DEBUG] ✅ RAW body ontvangen (content-type='{content_type}'):\n{body_text}")
            # Probeer alsnog JSON te decoderen
            try:
                body_dict = json.loads(body_text)
                safe_print(f"[DEBUG] ✅ RAW bleek JSON na parse:\n{json.dumps(body_dict, indent=2)}")
            except Exception:
                body_dict = {"raw_body": body_text}
    except Exception as e:
        safe_print(f"[ERROR] Fout bij lezen/parsen callback body: {e}")
        traceback.print_exc(file=sys.stdout)
        body_dict = {"parse_error": str(e)}

    # Sane defaults
    verified = bool(body_dict.get("verified", True))
    holder = body_dict.get("holder") or body_dict.get("subject") or "Onbekend"

    # Sessiestatus bijwerken
    sessions[request_id].update({
        "status": "completed" if verified else "failed",
        "verified": verified,
        "holder": holder,
        "result": body_dict,
        "completed_at": now_iso()
    })

    safe_print(f"[DEBUG] ✅ Verificatie opgeslagen voor {request_id}\n")

    # Paradym verwacht 2xx — 200 OK is prima
    return JSONResponse({"success": True, "verified": verified})

# -----------------------------------------------------
# 3️⃣ Status & debug
# -----------------------------------------------------
@app.get("/presentation/{request_id}/status")
async def get_status(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")
    return sessions[request_id]

@app.get("/presentation/{request_id}/raw")
async def get_raw(request_id: str):
    if request_id not in sessions:
        raise HTTPException(status_code=404, detail="Not found")
    raw = sessions[request_id].get("result") or {}
    try:
        return JSONResponse(raw)
    except Exception:
        return PlainTextResponse(str(raw))

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
    safe_print("🚀 Starting Paradym Login Verifier API on port 8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
