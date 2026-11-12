"""Encrypted single-owner Cadran state storage on Render PostgreSQL.

The service stores no bank password or raw banking API key. Application data,
including the Enable Banking consent session, is encrypted before writing to
PostgreSQL with an independent Fernet key stored only in Render environment.
The database is only reachable from the server, never from browser JavaScript.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

import psycopg
from cryptography.fernet import Fernet, InvalidToken

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DATA_KEY = os.environ.get("CADRAN_DATA_KEY", "").strip()
MAX_BYTES = 8_000_000
SLOTS = frozenset(("manual", "bank", "consent"))


class StorageError(RuntimeError):
    pass


class StorageConflict(StorageError):
    pass


def configured() -> bool:
    if not DATABASE_URL or not DATA_KEY:
        return False
    try:
        Fernet(DATA_KEY.encode("ascii"))
    except (ValueError, TypeError, UnicodeError):
        return False
    return True


def _cipher() -> Fernet:
    if not configured():
        raise StorageError("Le stockage sécurisé de Cadran n'est pas configuré.")
    return Fernet(DATA_KEY.encode("ascii"))


def _connect():
    if not configured():
        raise StorageError("Stockage sécurisé non configuré.")
    return psycopg.connect(DATABASE_URL, connect_timeout=10, autocommit=False)


@lru_cache(maxsize=1)
def ensure_schema() -> bool:
    # No personal financial data or secrets enter the database's plaintext
    # columns; the only lookup key is a fixed storage slot.
    with _connect() as conn:
        conn.execute("""
          CREATE TABLE IF NOT EXISTS cadran_private_state (
            slot VARCHAR(12) PRIMARY KEY,
            revision BIGINT NOT NULL DEFAULT 1,
            data BYTEA NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT cadran_slot CHECK (slot IN ('manual', 'bank', 'consent'))
          )
        """)
    return True


def read(slot: str) -> tuple[dict | None, int]:
    if slot not in SLOTS:
        raise ValueError("Invalid private storage slot")
    ensure_schema()
    with _connect() as conn:
        row = conn.execute(
            "SELECT revision, data FROM cadran_private_state WHERE slot = %s",
            (slot,),
        ).fetchone()
    if not row:
        return None, 0
    try:
        value = json.loads(_cipher().decrypt(bytes(row[1])).decode("utf-8"))
        if not isinstance(value, dict):
            raise StorageError("Stockage chiffré endommagé.")
        return value, int(row[0])
    except (InvalidToken, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise StorageError("Impossible de déchiffrer les données Cadran.") from exc


def write(slot: str, value: dict, *, expected_revision: int | None = None) -> int:
    if slot not in SLOTS or not isinstance(value, dict):
        raise ValueError("Invalid private state")
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_BYTES:
        raise ValueError("Données trop volumineuses (8 Mo maximum).")
    ensure_schema()
    encrypted = _cipher().encrypt(encoded)
    with _connect() as conn:
        row = conn.execute(
            "SELECT revision FROM cadran_private_state WHERE slot = %s FOR UPDATE",
            (slot,),
        ).fetchone()
        current = int(row[0]) if row else 0
        if expected_revision is not None and current != expected_revision:
            raise StorageConflict("Les données ont changé sur un autre appareil.")
        if row:
            revision = current + 1
            conn.execute(
                "UPDATE cadran_private_state "
                "SET revision=%s, data=%s, updated_at=now() WHERE slot=%s",
                (revision, encrypted, slot),
            )
        else:
            revision = 1
            conn.execute(
                "INSERT INTO cadran_private_state(slot, revision, data) "
                "VALUES (%s, %s, %s)",
                (slot, revision, encrypted),
            )
    return revision


def delete(slot: str) -> None:
    if slot not in SLOTS:
        raise ValueError("Invalid private storage slot")
    ensure_schema()
    with _connect() as conn:
        conn.execute("DELETE FROM cadran_private_state WHERE slot=%s", (slot,))
