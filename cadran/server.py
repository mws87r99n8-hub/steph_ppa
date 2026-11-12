"""Cadran / Enable Banking — read-only single-user open banking gateway.

Provider: https://enablebanking.com/docs/api/reference
The API key never reaches the browser. The external consent session ID is kept
in an authenticated, encrypted HttpOnly browser cookie; no payment APIs exist.
The owner must configure private Render environment variables manually.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlencode, urlparse
from uuid import UUID

import httpx
import jwt
import storage
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "").strip().rstrip("/")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
APP_SESSION_SECRET = os.environ.get("APP_SESSION_SECRET", "")
EB_APP_ID = os.environ.get("ENABLE_BANKING_APP_ID", "").strip()
EB_PRIVATE_KEY = os.environ.get("ENABLE_BANKING_PRIVATE_KEY", "").replace("\\n", "\n").strip()
API_BASE = "https://api.enablebanking.com"
LOGIN_COOKIE = "cadran_auth"
STATE_COOKIE = "cadran_eb_state"
CONSENT_COOKIE = "cadran_eb_consent"
LOGIN_TTL = 4 * 3600
CONSENT_TTL = 90 * 86400
LOGGER = logging.getLogger("cadran")
ATTEMPTS: dict[str, deque] = defaultdict(deque)
app = FastAPI(title="Cadran", docs_url=None, redoc_url=None, openapi_url=None)

def configured() -> bool:
    return bool(PUBLIC_URL.startswith("https://") and len(APP_PASSWORD) >= 12
                and len(APP_SESSION_SECRET) >= 32 and EB_APP_ID
                and EB_PRIVATE_KEY.startswith("-----BEGIN ") and "PRIVATE KEY-----" in EB_PRIVATE_KEY)

def cipher() -> Fernet:
    if len(APP_SESSION_SECRET) < 32:
        raise HTTPException(503, "Clé serveur manquante.")
    secret = hashlib.sha256(("cadran-eb-cookies:"+APP_SESSION_SECRET).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(secret))

def encode_cookie(data: dict) -> str:
    return cipher().encrypt(json.dumps(data, separators=(",", ":")).encode()).decode()

def decode_cookie(value: str) -> dict | None:
    if not value or len(value) > 3600 or len(APP_SESSION_SECRET) < 32:
        return None
    try:
        d = json.loads(cipher().decrypt(value.encode()).decode())
        return d if isinstance(d, dict) and d.get("exp", 0) > time.time() else None
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError):
        return None

def login_cookie(request: Request) -> bool:
    payload = decode_cookie(request.cookies.get(LOGIN_COOKIE, ""))
    return bool(payload and payload.get("type") == "owner")

def bank_cookie(request: Request) -> dict | None:
    d = decode_cookie(request.cookies.get(CONSENT_COOKIE, ""))
    return d if d and d.get("type") == "consent" else None

def require_login(request: Request):
    if not configured():
        raise HTTPException(503, "Enable Banking n'est pas configuré dans Render.")
    if not login_cookie(request):
        raise HTTPException(401, "Session expirée. Déverrouillez le module bancaire.")

async def shared_consent(request: Request) -> dict | None:
    saved = bank_cookie(request)
    if saved:
        return saved
    if storage.configured():
        stored, _ = await asyncio.to_thread(storage.read, "consent")
        if stored and stored.get("exp", 0) > time.time() and stored.get("type") == "consent":
            return stored
    return None

async def require_consent(request: Request) -> dict:
    require_login(request)
    value = await shared_consent(request)
    if not value:
        raise HTTPException(409, "Aucun consentement bancaire actif. Connectez Société Générale.")
    return value

def cookie(response, name, data, ttl):
    response.set_cookie(name, encode_cookie(data), max_age=ttl,
                        httponly=True, secure=True, samesite="lax", path="/")

def make_jwt() -> str:
    now = int(time.time())
    try:
        return jwt.encode(
            {"iss": "enablebanking.com", "aud": "api.enablebanking.com",
             "iat": now, "exp": now + 1200},
            EB_PRIVATE_KEY, algorithm="RS256",
            headers={"kid": EB_APP_ID, "typ": "JWT"}
        )
    except Exception:
        raise HTTPException(503, "Clé RSA Enable Banking invalide.")

async def eb(method: str, path: str, *, params=None, body=None) -> dict:
    # Only fixed, application-generated Enable Banking API paths may be requested.
    if not path.startswith(("/aspsps", "/auth", "/sessions", "/accounts/")) or urlparse(path).netloc:
        raise HTTPException(500, "Route bancaire refusée.")
    headers = {"Authorization": "Bearer " + make_jwt(), "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(base_url=API_BASE, timeout=25.0, follow_redirects=False) as client:
            response = await client.request(method, path, params=params, json=body, headers=headers)
    except httpx.RequestError:
        raise HTTPException(502, "Enable Banking est temporairement inaccessible.")
    if response.status_code == 429:
        raise HTTPException(429, "Limite de consultation bancaire atteinte. Réessayez plus tard.")
    if response.status_code >= 400:
        # Never expose provider raw error objects (can contain bank details).
        LOGGER.warning("Enable Banking HTTP %s on %s", response.status_code, path.split("?")[0])
        raise HTTPException(502, "Enable Banking a refusé la demande. Vérifiez les autorisations et la validité du consentement.")
    if response.status_code == 204:
        return {}
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(502, "Réponse bancaire incorrecte.")
    if not isinstance(data, dict):
        raise HTTPException(502, "Réponse bancaire non reconnue.")
    return data

@app.middleware("http")
async def secure(request: Request, call_next):
    if request.url.path.startswith(("/api/bank/", "/api/data/")) and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin", "")
        if origin and origin != PUBLIC_URL:
            return JSONResponse({"error": "Origine non autorisée."}, status_code=403)
        if request.headers.get("sec-fetch-site") in ("cross-site", "same-site"):
            return JSONResponse({"error": "Requête intersite refusée."}, status_code=403)
        if request.headers.get("x-requested-with") != "Cadran":
            return JSONResponse({"error": "En-tête de sécurité manquant."}, status_code=403)
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
    if request.url.path.startswith("/api/") or request.url.path in ("/", "/index.html"):
        response.headers["Cache-Control"] = "no-store"
    if PUBLIC_URL.startswith("https://"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

@app.exception_handler(HTTPException)
async def error_handler(request: Request, exc: HTTPException):
    return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)

class PasswordInput(BaseModel):
    password: str = Field(min_length=1, max_length=512)

@app.get("/healthz")
async def healthz():
    return {"ok": True, "provider": "Enable Banking", "bankConfigured": configured(), "storageConfigured": storage.configured()}

class ManualStateUpdate(BaseModel):
    revision: int = Field(ge=0)
    state: dict


def sanitize_manual_state(value: dict) -> dict:
    """Only personal manual data may be changed from the browser.

    Provider accounts and transactions are managed by the bank sync route and
    cannot be overwritten by a browser-side backup or a second device.
    """
    if not isinstance(value, dict):
        raise HTTPException(422, "Format de sauvegarde incorrect.")
    for key in ("accounts", "transactions", "recurring", "imported"):
        if key in value and not isinstance(value[key], list):
            raise HTTPException(422, "Structure de sauvegarde incorrecte.")
    if not isinstance(value.get("budgets", {}), dict) or not isinstance(value.get("settings", {}), dict):
        raise HTTPException(422, "Budgets ou paramètres incorrects.")
    accounts = [a for a in value.get("accounts", []) if isinstance(a, dict)
                and a.get("manual") is not False and not a.get("enableAccountId")]
    ids = {str(a.get("id")) for a in accounts}
    txns = [t for t in value.get("transactions", []) if isinstance(t, dict)
            and t.get("source") != "enablebanking"
            and str(t.get("accountId")) in ids]
    recurring = [r for r in value.get("recurring", []) if isinstance(r, dict)
                 and str(r.get("accountId", "")) in ids]
    if len(accounts) > 300 or len(txns) > 30000 or len(recurring) > 10000:
        raise HTTPException(413, "Trop d'enregistrements pour cette sauvegarde.")
    return {
        "version": 1, "demo": False,
        "accounts": accounts, "transactions": txns,
        "budgets": value.get("budgets", {}),
        "recurring": recurring,
        "settings": value.get("settings", {"hidden": False}),
        "imported": value.get("imported", []),
    }


@app.get("/api/data/status")
async def data_status(request: Request):
    return {"storageConfigured": storage.configured(),
            "authenticated": bool(configured() and login_cookie(request))}


@app.get("/api/data")
async def load_private_data(request: Request):
    require_login(request)
    if not storage.configured():
        raise HTTPException(503, "Base de données Cadran non raccordée sur Render.")
    try:
        manual, revision = await asyncio.to_thread(storage.read, "manual")
        bank, _ = await asyncio.to_thread(storage.read, "bank")
    except Exception:
        LOGGER.error("Unable to load encrypted user data from private storage")
        raise HTTPException(503, "Stockage sécurisé inaccessible. Aucune donnée n'a été modifiée.")
    return {"manual": manual, "revision": revision,
            "bank": bank, "hasManualData": manual is not None}


@app.put("/api/data/manual")
async def save_private_data(request: Request, payload: ManualStateUpdate):
    require_login(request)
    if not storage.configured():
        raise HTTPException(503, "Base de données Cadran non raccordée sur Render.")
    clean = sanitize_manual_state(payload.state)
    try:
        revision = await asyncio.to_thread(
            storage.write, "manual", clean, expected_revision=payload.revision
        )
    except storage.StorageConflict:
        raise HTTPException(409, "Données modifiées sur un autre appareil. Rechargez Cadran avant de réessayer.")
    except ValueError:
        raise HTTPException(413, "Sauvegarde trop volumineuse.")
    except Exception:
        LOGGER.error("Unable to save encrypted user data to private storage")
        raise HTTPException(503, "Sauvegarde serveur impossible. Ne fermez pas la page avant d'avoir exporté un JSON.")
    return {"saved": True, "revision": revision}


@app.get("/api/bank/status")
async def status(request: Request):
    logged = configured() and login_cookie(request)
    consent = await shared_consent(request) if logged else None
    return {"provider": "Enable Banking", "readOnly": True, "selectedBank": "Société Générale",
            "configured": configured(), "authenticated": bool(logged),
            "connected": bool(consent),
            "consentValidUntil": consent.get("valid_until") if consent else None}

@app.post("/api/bank/login")
async def login(request: Request, body: PasswordInput):
    if not configured():
        raise HTTPException(503, "Module en attente de configuration Enable Banking sur Render.")
    client_ip = request.client.host if request.client else "?"
    events = ATTEMPTS[client_ip]
    now = time.time()
    while events and events[0] < now - 15*60:
        events.popleft()
    if len(events) >= 6:
        raise HTTPException(429, "Trop de tentatives. Réessayez dans 15 minutes.")
    if not hmac.compare_digest(body.password.encode(), APP_PASSWORD.encode()):
        events.append(now)
        raise HTTPException(401, "Mot de passe incorrect.")
    events.clear()
    response = JSONResponse({"authenticated": True})
    cookie(response, LOGIN_COOKIE, {"type": "owner", "exp": now + LOGIN_TTL,
                                    "nonce": secrets.token_hex(12)}, LOGIN_TTL)
    return response

@app.post("/api/bank/logout")
async def logout():
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(LOGIN_COOKIE, path="/")
    response.delete_cookie(STATE_COOKIE, path="/")
    return response

@app.post("/api/bank/connect")
async def connect(request: Request):
    require_login(request)
    banks = await eb("GET", "/aspsps", params={"country": "FR", "psu_type": "personal"})
    entries = banks.get("aspsps", [])
    target = next((b for b in entries if isinstance(b, dict)
                   and b.get("name") == "Société Générale" and b.get("country") == "FR"
                   and "personal" in (b.get("psu_types") or ["personal"])), None)
    if not target:
        raise HTTPException(503, "Connecteur Société Générale personnel non disponible dans le catalogue Enable Banking.")
    max_valid = int(target.get("maximum_consent_validity") or CONSENT_TTL)
    seconds = min(CONSENT_TTL - 3600, max_valid - 600)
    if seconds < 3600:
        raise HTTPException(503, "Durée du consentement SG indisponible.")
    valid_until = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    state = secrets.token_urlsafe(32)
    payload = {
        "access": {"balances": True, "transactions": True, "valid_until": valid_until.isoformat()},
        "aspsp": {"name": "Société Générale", "country": "FR"},
        "psu_type": "personal",
        "state": state,
        "language": "fr",
        "redirect_url": PUBLIC_URL + "/api/bank/callback",
    }
    result = await eb("POST", "/auth", body=payload)
    url = result.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or not (
            parsed.hostname == "enablebanking.com" or parsed.hostname.endswith(".enablebanking.com")):
        raise HTTPException(502, "URL d'autorisation bancaire non autorisée.")
    response = JSONResponse({"url": url, "bank": "Société Générale"})
    cookie(response, STATE_COOKIE, {"type": "state", "value": state, "exp": time.time() + 15*60}, 15*60)
    return response

@app.get("/api/bank/callback")
async def callback(request: Request):
    # The bank returns a one-time code; exchange it on the server, never in JS.
    fallback = PUBLIC_URL + "/?bank_callback=error"
    if not configured() or not login_cookie(request):
        return RedirectResponse(fallback, status_code=303)
    saved = decode_cookie(request.cookies.get(STATE_COOKIE, ""))
    code, state, remote_error = (request.query_params.get(k, "") for k in ("code", "state", "error"))
    if (not saved or saved.get("type") != "state" or
            not hmac.compare_digest(str(saved.get("value", "")), state) or
            remote_error or not code or len(code) > 4096):
        response = RedirectResponse(fallback, status_code=303)
        response.delete_cookie(STATE_COOKIE, path="/")
        return response
    try:
        result = await eb("POST", "/sessions", body={"code": code})
        sid = str(result.get("session_id", ""))
        UUID(sid)
        until = result.get("access", {}).get("valid_until")
        if not until:
            raise ValueError("consent expiry missing")
        exp = datetime.fromisoformat(until.replace("Z", "+00:00")).timestamp()
        if exp <= time.time() + 60:
            raise ValueError("consent expired")
    except (HTTPException, ValueError, TypeError, KeyError, AttributeError):
        response = RedirectResponse(fallback, status_code=303)
        response.delete_cookie(STATE_COOKIE, path="/")
        return response
    response = RedirectResponse(PUBLIC_URL + "/?bank_callback=1", status_code=303)
    ttl = max(60, min(CONSENT_TTL, int(exp - time.time())))
    consent_data = {"type": "consent", "session": sid, "valid_until": until,
                    "exp": time.time() + ttl}
    if storage.configured():
        try:
            await asyncio.to_thread(storage.write, "consent", consent_data)
        except Exception:
            LOGGER.error("Unable to persist encrypted consent to private storage")
    cookie(response, CONSENT_COOKIE, consent_data, ttl)
    response.delete_cookie(STATE_COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return response

def normalized_currency(value) -> str:
    """Normalize ISO 4217 values without inventing an exchange rate."""
    if not isinstance(value, str):
        return ""
    code = value.strip().upper()
    if code == "€":
        return "EUR"
    # Never echo arbitrary provider data in diagnostic messages.
    return code if len(code) == 3 and code.isascii() and code.isalpha() else ("INCONNUE" if code else "")


def safe_money(raw) -> float:
    try:
        v = Decimal(str(raw))
        if not v.is_finite():
            raise ValueError("nonfinite")
        return float(round(v, 2))
    except (InvalidOperation, TypeError, ValueError):
        raise HTTPException(502, "Montant bancaire incorrect.")

def global_id(value: str) -> str:
    return hmac.new(APP_SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()

def normalized_tx(tx: dict, account_id: str) -> dict | None:
    if tx.get("status") not in ("BOOK", None):
        return None
    raw_amount = tx.get("transaction_amount") or {}
    if normalized_currency(raw_amount.get("currency")) != "EUR":
        return None
    amount = abs(safe_money(raw_amount.get("amount")))
    indicator = tx.get("credit_debit_indicator")
    if indicator not in ("CRDT", "DBIT"):
        return None
    amount = amount if indicator == "CRDT" else -amount
    booked = str(tx.get("booking_date") or tx.get("value_date") or tx.get("transaction_date") or "")
    if len(booked) < 10:
        return None
    merchant = " ".join(filter(None, [
        (tx.get("creditor") or {}).get("name") if amount < 0 else (tx.get("debtor") or {}).get("name"),
        " / ".join(str(x) for x in (tx.get("remittance_information") or [])[:2]) if isinstance(tx.get("remittance_information"), list) else "",
        tx.get("note") or ""
    ])).strip()
    merchant = merchant or str(tx.get("entry_reference") or "Opération bancaire")
    ref = str(tx.get("transaction_id") or tx.get("entry_reference") or "")
    fingerprint = json.dumps([
        account_id, ref, booked, str(amount), merchant,
        str(tx.get("balance_after_transaction") or "")
    ], sort_keys=True, ensure_ascii=False)
    return {"id": global_id(fingerprint), "account_id": account_id, "amount": amount,
            "date": booked[:10], "clean_description": merchant[:160],
            "provider_description": merchant[:160], "future": False, "deleted": False,
            "currency_code": "EUR"}

@app.post("/api/bank/sync")
async def sync(request: Request):
    consent = await require_consent(request)
    sid = str(consent.get("session") or "")
    try:
        UUID(sid)
    except ValueError:
        raise HTTPException(409, "Session bancaire incorrecte. Reconnectez SG.")
    session = await eb("GET", f"/sessions/{sid}")
    if session.get("status") != "AUTHORIZED":
        raise HTTPException(409, "Consentement SG expiré ou révoqué. Reconnectez la banque.")
    account_data = session.get("accounts_data") or []
    account_ids = session.get("accounts") or []
    if not isinstance(account_data, list) or not isinstance(account_ids, list):
        raise HTTPException(502, "Liste des comptes Enable Banking incorrecte.")
    # The API exposes both accounts_data and accounts. Use the union of valid
    # session-scoped UUIDs: the short accounts list can still be present when
    # accounts_data is empty. No bank account IDs are returned to the browser.
    authorized = {}
    for mapping in account_data:
        if not isinstance(mapping, dict):
            continue
        try:
            uid = str(UUID(str(mapping.get("uid") or "")))
        except (ValueError, TypeError, AttributeError):
            continue
        authorized[uid] = mapping
    for raw_uid in account_ids:
        try:
            uid = str(UUID(str(raw_uid)))
        except (ValueError, TypeError, AttributeError):
            continue
        authorized.setdefault(uid, {"uid": uid})
    if not authorized:
        LOGGER.warning("SG session authorized but no accessible accounts: accounts_data=%d accounts=%d",
                       len(account_data), len(account_ids))
        raise HTTPException(
            409,
            "Consentement SG valide, mais Enable Banking ne renvoie aucun compte. "
            "Si l'application est en Production restreinte, associez les comptes SG "
            "dans Enable Banking (API applications > comptes liés), puis renouvelez "
            "le consentement dans Cadran."
        )
    accounts, transactions, seen = [], [], set()
    rejected_currencies = defaultdict(int)
    date_from = (datetime.now(timezone.utc) - timedelta(days=89)).date().isoformat()
    for uid, mapping in list(authorized.items())[:30]:
        public_account_id = global_id(str(mapping.get("identification_hash") or uid))
        detail = await eb("GET", f"/accounts/{uid}/details")
        # The account-level currency can legitimately be XXX (unspecified or
        # multi-currency). In that case, use the explicit balance currency:
        # XXX must never be interpreted automatically as EUR.
        currency = normalized_currency(detail.get("currency"))
        if currency not in ("EUR", "XXX", ""):
            rejected_currencies[currency] += 1
            continue
        balances = await eb("GET", f"/accounts/{uid}/balances")
        items = balances.get("balances", [])
        if not isinstance(items, list):
            raise HTTPException(502, "Format des soldes bancaires non reconnu.")
        euro_balances = [
            b for b in items
            if isinstance(b, dict) and isinstance(b.get("balance_amount"), dict)
            and normalized_currency(b["balance_amount"].get("currency")) == "EUR"
        ]
        selected = next((
            b for kind in ("CLBD", "ITBD", "CLAV", "ITAV", "XPCD", "PRCD", "OPBD")
            for b in euro_balances if b.get("balance_type") == kind
        ), euro_balances[0] if euro_balances else None)
        if selected is None:
            # A bank can expose several currencies. Skip only this account
            # instead of making all other authorized EUR accounts unavailable.
            codes = {
                normalized_currency(b.get("balance_amount", {}).get("currency"))
                for b in items if isinstance(b, dict)
                and isinstance(b.get("balance_amount"), dict)
            }
            for code in codes or {currency or "INCONNUE"}:
                rejected_currencies[code or "INCONNUE"] += 1
            continue
        balance = safe_money((selected.get("balance_amount") or {}).get("amount"))
        accounts.append({"id": public_account_id,
                         "name": str(detail.get("name") or "Compte Société Générale")[:100],
                         "bank": "Société Générale",
                         "balance": balance, "type": str(detail.get("cash_account_type") or "checking"),
                         "currency_code": "EUR", "updated_at": datetime.now(timezone.utc).date().isoformat()})
        key = None
        for _ in range(40):
            params = {"date_from": date_from, "transaction_status": "BOOK"}
            if key:
                params["continuation_key"] = key
            chunk = await eb("GET", f"/accounts/{uid}/transactions", params=params)
            rows = chunk.get("transactions") or []
            if not isinstance(rows, list):
                raise HTTPException(502, "Opérations bancaires incorrectes.")
            for tx in rows:
                item = normalized_tx(tx, public_account_id)
                if item and item["id"] not in seen:
                    transactions.append(item)
                    seen.add(item["id"])
            nxt = chunk.get("continuation_key")
            if not nxt:
                break
            if nxt == key:
                raise HTTPException(502, "Pagination bancaire interrompue.")
            key = nxt
        else:
            raise HTTPException(502, "Trop de pages de transactions bancaires.")
    if not accounts:
        if rejected_currencies:
            summary = ", ".join(f"{code} ({count})" for code, count in sorted(rejected_currencies.items()))
            LOGGER.warning("SG no EUR balances; observed balance currencies: %s", summary)
            raise HTTPException(409,
                "Aucun solde en euros fourni par Enable Banking pour ces comptes. "
                "Devises des soldes : " + summary + ". "
                "Le code XXX au niveau du compte n'est pas bloquant ; vérifiez "
                "la devise des soldes dans Enable Banking.")
        raise HTTPException(409, "Comptes SG autorisés, mais aucun solde EUR exploitable identifié.")
    result = {"source": "Enable Banking", "accounts": accounts,
              "transactions": transactions, "lastSync": int(time.time()),
              "consentValidUntil": consent.get("valid_until"),
              "periodStart": date_from}
    if storage.configured():
        try:
            await asyncio.to_thread(storage.write, "bank", result)
            # Also share existing valid browser consent with standalone PWA.
            await asyncio.to_thread(storage.write, "consent", consent)
        except Exception:
            LOGGER.error("Unable to persist encrypted bank snapshot")
            raise HTTPException(503, "Comptes récupérés, mais sauvegarde sécurisée momentanément indisponible. Réessayez.")
    return result

@app.post("/api/bank/disconnect")
async def disconnect(request: Request):
    consent = await require_consent(request)
    sid = str(consent.get("session") or "")
    try:
        UUID(sid)
    except ValueError:
        raise HTTPException(409, "Session incorrecte.")
    await eb("DELETE", f"/sessions/{sid}")
    if storage.configured():
        try:
            await asyncio.to_thread(storage.delete, "consent")
            await asyncio.to_thread(storage.delete, "bank")
        except Exception:
            LOGGER.error("Consent revoked; private storage cleanup failed")
            raise HTTPException(503, "Consentement révoqué, mais suppression serveur à vérifier.")
    response = JSONResponse({"disconnected": True})
    response.delete_cookie(CONSENT_COOKIE, path="/")
    return response

FILES = {"/": "index.html", "/index.html": "index.html",
         "/manifest.webmanifest": "manifest.webmanifest", "/icon.svg": "icon.svg",
         "/sw.js": "sw.js", "/privacy.html": "privacy.html", "/terms.html": "terms.html"}
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
try:
    INLINE_JS = HTML.split("<script>", 1)[1].split("</script>", 1)[0]
except IndexError:
    INLINE_JS = ""
INLINE_SCRIPT_HASH = base64.b64encode(hashlib.sha256(INLINE_JS.encode()).digest()).decode()

@app.get("/{path:path}", include_in_schema=False)
async def serve_assets(path: str):
    filename = FILES.get("/" + path)
    if not filename:
        raise HTTPException(404, "Resource unavailable.")
    full_path = ROOT / filename
    mime = {".html": "text/html; charset=utf-8",
            ".webmanifest": "application/manifest+json",
            ".svg": "image/svg+xml", ".js": "text/javascript"}.get(full_path.suffix)
    return FileResponse(full_path, media_type=mime)
