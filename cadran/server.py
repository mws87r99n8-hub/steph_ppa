"""Retired endpoint. No banking or personal-finance application is served."""
from __future__ import annotations
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from uuid import UUID

import httpx
import jwt
import storage
from fastapi import FastAPI, Request
from fastapi.responses import Response

LOGGER = logging.getLogger("retired")
PURGE_FLAG = "CONFIRMED_CADRAN_PURGE_2026_11_12"

async def purge_banking_and_database():
    """User-authorized deletion; only touches Cadran's private table."""
    if not storage.configured():
        LOGGER.error("CADRAN_PURGE: FAILED_DB_NOT_CONFIGURED")
        return
    consent = None
    try:
        consent, _ = await asyncio.to_thread(storage.read, "consent")
    except Exception:
        LOGGER.warning("CADRAN_PURGE: consent not readable; continuing local deletion")
    if isinstance(consent, dict) and consent.get("session"):
        try:
            sid = str(UUID(str(consent["session"])))
            private_key = os.getenv("ENABLE_BANKING_PRIVATE_KEY", "").replace("\\n", "\n").strip()
            app_id = os.getenv("ENABLE_BANKING_APP_ID", "").strip()
            if not private_key or not app_id:
                LOGGER.warning("CADRAN_PURGE: BANK_REVOKE_CREDENTIALS_UNAVAILABLE")
            else:
                now = int(time.time())
                token = jwt.encode(
                    {"iss": "enablebanking.com", "aud": "api.enablebanking.com",
                     "iat": now, "exp": now + 1200},
                    private_key, algorithm="RS256",
                    headers={"kid": app_id, "typ": "JWT"}
                )
                async with httpx.AsyncClient(timeout=25.0, follow_redirects=False) as client:
                    response = await client.delete(
                        "https://api.enablebanking.com/sessions/" + sid,
                        headers={"Authorization": "Bearer " + token, "Accept": "application/json"}
                    )
                if response.status_code in (200, 202, 204, 404, 410):
                    LOGGER.warning("CADRAN_PURGE: BANK_CONSENT_REVOKED_OR_ABSENT")
                else:
                    LOGGER.warning("CADRAN_PURGE: BANK_REVOKE_UNCONFIRMED_HTTP_%d", response.status_code)
        except Exception:
            LOGGER.warning("CADRAN_PURGE: BANK_REVOKE_UNCONFIRMED")
    else:
        LOGGER.warning("CADRAN_PURGE: NO_STORED_CONSENT")
    try:
        def drop_private_table():
            with storage._connect() as conn:
                conn.execute("DROP TABLE IF EXISTS public.cadran_private_state")
            with storage._connect() as conn:
                return conn.execute(
                    "SELECT to_regclass('public.cadran_private_state') IS NULL"
                ).fetchone()[0]
        dropped = await asyncio.to_thread(drop_private_table)
        LOGGER.warning("CADRAN_PURGE: PRIVATE_TABLE_DELETED=%s", bool(dropped))
    except Exception:
        LOGGER.error("CADRAN_PURGE: PRIVATE_TABLE_DELETE_FAILED")

@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("CADRAN_PURGE_NOW") == PURGE_FLAG:
        await purge_banking_and_database()
    yield

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None, lifespan=lifespan)
def blank_response(status: int):
    response = Response(content=b"", status_code=status, media_type="text/plain",
                        headers={"Cache-Control": "no-store, no-cache, must-revalidate",
                                 "Clear-Site-Data": '"cache", "cookies", "storage"'})
    for name in ("cadran_auth", "cadran_eb_state", "cadran_eb_consent"):
        response.delete_cookie(name, path="/")
    return response

@app.api_route("/", methods=["GET", "HEAD"])
async def home(request: Request):
    return blank_response(200)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def gone(path: str):
    return blank_response(410)
