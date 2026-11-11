"""Cadran — private single-user Bridge Aggregation V3 gateway.
Only the account owner may configure APP_PASSWORD, APP_SESSION_SECRET,
BRIDGE_CLIENT_ID, BRIDGE_CLIENT_SECRET, and BRIDGE_USER_EMAIL.
No payment initiation, no storage of bank credentials or tokens.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse
import secrets

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "").strip().rstrip("/")
PASSWORD = os.environ.get("APP_PASSWORD", "")
SESSION_SECRET = os.environ.get("APP_SESSION_SECRET", "")
CLIENT_ID = os.environ.get("BRIDGE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("BRIDGE_CLIENT_SECRET", "")
BRIDGE_EMAIL = os.environ.get("BRIDGE_USER_EMAIL", "")
CONFIGURED = all([PUBLIC_URL.startswith("https://"), PASSWORD, SESSION_SECRET,
                  CLIENT_ID, CLIENT_SECRET, "@" in BRIDGE_EMAIL])
API_BASE = "https://api.bridgeapi.io"
BRIDGE_VERSION = "2025-01-15"
COOKIE = "cadran_bank_session"
REQUESTS: dict[str, deque] = defaultdict(deque)
app = FastAPI(title="Cadran Bridge", docs_url=None, redoc_url=None, openapi_url=None)

class Login(BaseModel):
    password: str = Field(min_length=1, max_length=1024)

class BridgeFailure(Exception):
    def __init__(self, status):
        self.status = status

def has_session(request: Request) -> bool:
    if not SESSION_SECRET:
        return False
    try:
        val = request.cookies.get(COOKIE, "")
        raw, sig = val.rsplit(".", 1)
        mac = hmac.new(SESSION_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, sig):
            return False
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        return payload.get("session") == "cadran" and int(payload.get("exp", 0)) > time.time()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False

def check_session(request: Request):
    if not CONFIGURED:
        raise HTTPException(503, "Bridge non configuré. Les variables d'environnement sont requises côté serveur.")
    if not has_session(request):
        raise HTTPException(401, "Session Cadran expirée. Authentifiez-vous.")

def make_session():
    payload = {"session": "cadran", "exp": int(time.time()) + 4 * 3600,
               "nonce": secrets.token_hex(16)}
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = hmac.new(SESSION_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return raw + "." + sig

@app.middleware("http")
async def security(request: Request, call_next):
    if request.url.path.startswith("/api/bank/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin", "")
        # Require genuine same-origin browser requests; no embedded third-party forms.
        if origin and origin != PUBLIC_URL:
            return JSONResponse({"error": "Origine non autorisée"}, status_code=403)
        if request.headers.get("sec-fetch-site") in ("cross-site", "same-site"):
            return JSONResponse({"error": "Requête intersite non autorisée"}, status_code=403)
        if request.headers.get("x-requested-with") != "Cadran":
            return JSONResponse({"error": "En-tête de sécurité manquant"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'sha256-" + INLINE_SCRIPT_HASH + "'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "font-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if PUBLIC_URL.startswith("https://"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

@app.exception_handler(HTTPException)
async def api_error(request: Request, exc: HTTPException):
    return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)

@app.get("/api/bank/status")
async def status(request: Request):
    return {"configured": CONFIGURED, "authenticated": bool(CONFIGURED and has_session(request)),
            "provider": "Bridge", "readOnly": True, "selectedBank": "Société Générale"}

@app.get("/healthz")
async def health():
    return {"ok": True, "bridgeConfigured": CONFIGURED}

@app.post("/api/bank/login")
async def login(request: Request, body: Login):
    if not CONFIGURED:
        raise HTTPException(503, "Module bancaire désactivé. Configurez vos accès Bridge sur Render.")
    address = request.client.host if request.client else "unknown"
    events = REQUESTS[address]
    now = time.time()
    while events and events[0] < now - 900:
        events.popleft()
    if len(events) >= 8:
        raise HTTPException(429, "Trop de tentatives. Réessayez dans 15 minutes.")
    if not hmac.compare_digest(body.password.encode(), PASSWORD.encode()):
        events.append(now)
        raise HTTPException(401, "Mot de passe incorrect.")
    events.clear()
    response = JSONResponse({"authenticated": True})
    response.set_cookie(COOKIE, make_session(), max_age=4*3600,
                        httponly=True, secure=True, samesite="strict", path="/")
    return response

@app.post("/api/bank/logout")
async def logout():
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(COOKIE, path="/")
    return response

def user_reference():
    # Stable across Render restarts; never saved to ephemeral disk.
    return "cadran_" + hmac.new(SESSION_SECRET.encode(), b"bridge-personal-user", hashlib.sha256).hexdigest()[:32]

async def bridge_request(method, path, token="", body=None):
    if not path.startswith("/v3/aggregation/") or urlparse(path).netloc:
        raise HTTPException(500, "Endpoint Bridge refusé")
    headers = {"Client-Id": CLIENT_ID, "Client-Secret": CLIENT_SECRET,
               "Bridge-Version": BRIDGE_VERSION, "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        async with httpx.AsyncClient(base_url=API_BASE, timeout=35, follow_redirects=False) as client:
            resp = await client.request(method, path, headers=headers, json=body if body is not None else None)
    except httpx.HTTPError:
        raise HTTPException(502, "Service Bridge indisponible.")
    if resp.status_code >= 400:
        raise BridgeFailure(resp.status_code)
    if resp.status_code == 204:
        return {}
    try:
        return resp.json()
    except ValueError:
        raise HTTPException(502, "Réponse Bridge non conforme.")

async def authorized_token():
    ref = user_reference()
    try:
        result = await bridge_request("POST", "/v3/aggregation/authorization/token",
                                      body={"external_user_id": ref})
    except BridgeFailure as err:
        if err.status not in (400, 404):
            raise HTTPException(502, "Authentification Bridge refusée.")
        # Only create user when the stable external ID is unknown at Bridge.
        try:
            await bridge_request("POST", "/v3/aggregation/users",
                                 body={"external_user_id": ref})
            result = await bridge_request("POST", "/v3/aggregation/authorization/token",
                                          body={"external_user_id": ref})
        except BridgeFailure:
            raise HTTPException(502, "Création de la session Bridge impossible. Vérifiez le contrat et les clés.")
    token = result.get("access_token")
    if not isinstance(token, str) or not token:
        raise HTTPException(502, "Bridge n'a pas fourni de jeton valide.")
    return token

@app.post("/api/bank/connect")
async def connect(request: Request):
    check_session(request)
    token = await authorized_token()
    body = {"user_email": BRIDGE_EMAIL, "callback_url": PUBLIC_URL + "/?bank_callback=1"}
    try:
        data = await bridge_request("POST", "/v3/aggregation/connect-sessions",
                                    token=token, body=body)
    except BridgeFailure as err:
        if err.status == 429:
            raise HTTPException(429, "Limite de sessions Bridge atteinte.")
        raise HTTPException(502, "Impossible de créer la session Bridge. Vérifiez votre accès production et l'URL de retour.")
    url = data.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or not (
        parsed.hostname == "bridgeapi.io" or parsed.hostname.endswith(".bridgeapi.io")
    ):
        raise HTTPException(502, "URL de consentement Bridge refusée.")
    return {"url": url}

async def bridge_pages(path, token):
    all_items, visited = [], set()
    for _ in range(30):
        if path in visited or not path.startswith("/v3/aggregation/") or urlparse(path).netloc:
            raise HTTPException(502, "Pagination Bridge incorrecte.")
        visited.add(path)
        try:
            data = await bridge_request("GET", path, token=token)
        except BridgeFailure as err:
            if err.status == 429:
                raise HTTPException(429, "Limite de synchronisation Bridge atteinte.")
            raise HTTPException(502, "Récupération des données bancaires impossible.")
        rows = data.get("resources", [])
        if not isinstance(rows, list):
            raise HTTPException(502, "Réponse Bridge non conforme.")
        all_items.extend(rows)
        path = (data.get("pagination") or {}).get("next_uri")
        if not path:
            return all_items
    raise HTTPException(502, "Limite de pages Bridge dépassée.")

@app.post("/api/bank/sync")
async def sync(request: Request):
    check_session(request)
    token = await authorized_token()
    accounts = await bridge_pages("/v3/aggregation/accounts?limit=500", token)
    since = (date.today() - timedelta(days=365)).isoformat()
    operations = await bridge_pages(f"/v3/aggregation/transactions?limit=500&min_date={since}", token)
    safe_accounts = [
        {k: a.get(k) for k in ("id","name","balance","accounting_balance","type","currency_code","updated_at")}
        for a in accounts if a.get("data_access", "enabled") == "enabled"
    ]
    safe_operations = [
        {k: t.get(k) for k in ("id","account_id","amount","date","clean_description",
                                "provider_description","future","deleted","currency_code")}
        for t in operations
    ]
    return {"accounts": safe_accounts, "transactions": safe_operations,
            "lastSync": int(time.time()), "source": "Bridge"}

@app.post("/api/bank/disconnect")
async def disconnect(request: Request):
    check_session(request)
    token = await authorized_token()
    # Delete Bridge user and consent to terminate aggregation.
    # If no item is currently connected, deletion still ensures a clean state.
    try:
        items = await bridge_request("GET", "/v3/aggregation/items?limit=100", token=token)
        if not isinstance(items.get("resources", []), list):
            raise HTTPException(502, "Impossible de vérifier les connexions.")
        user = await bridge_request("POST", "/v3/aggregation/authorization/token",
                                    body={"external_user_id": user_reference()})
        user_uuid = (user.get("user") or {}).get("uuid")
        if not user_uuid or not isinstance(user_uuid, str):
            raise HTTPException(502, "Identifiant utilisateur Bridge indisponible.")
        await bridge_request("DELETE", f"/v3/aggregation/users/{user_uuid}")
    except BridgeFailure:
        raise HTTPException(502, "Révocation Bridge non confirmée.")
    return {"disconnected": True}

# Serve only explicit public assets; never expose environment, secrets or Python code.
FILES = {"/":"index.html", "/index.html":"index.html", "/manifest.webmanifest":"manifest.webmanifest",
         "/icon.svg":"icon.svg", "/sw.js":"sw.js"}

html = (ROOT / "index.html").read_text(encoding="utf-8")
try:
    inline_js = html.split("<script>", 1)[1].split("</script>", 1)[0]
except IndexError:
    inline_js = ""
INLINE_SCRIPT_HASH = base64.b64encode(hashlib.sha256(inline_js.encode()).digest()).decode()

@app.get("/{path:path}", include_in_schema=False)
async def assets(path: str):
    key = "/" + path
    if key not in FILES:
        raise HTTPException(404, "Not found")
    filename = ROOT / FILES[key]
    mimetypes = {".html":"text/html; charset=utf-8", ".svg":"image/svg+xml",
                 ".webmanifest":"application/manifest+json", ".js":"text/javascript"}
    return FileResponse(filename, media_type=mimetypes.get(filename.suffix))
