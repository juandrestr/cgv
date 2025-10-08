from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import os, psycopg

router = APIRouter()
_bearer = HTTPBearer(auto_error=True)

def _lazy_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    # Reuse main's auth (same pattern as vouchers_redeem)
    from main import get_current_user
    return get_current_user(creds)

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

def _principal_from_user(user):
    # Works for object-like or dict-like
    for k in ("user_uuid", "id", "sub", "email", "phone"):
        if hasattr(user, k):
            v = getattr(user, k)
            if v: return str(v)
        try:
            v = user.get(k)
            if v: return str(v)
        except Exception:
            pass
    return None

def _resolve_user_ids(conn, principal):
    """
    Return (users.id as int, users.user_uuid::text)
    wallets.user_id -> BIGINT (users.id)
    wallet_ledger.user_id -> UUID (users.user_uuid)
    """
    principal = str(principal)
    with conn.cursor() as cur:
        cur.execute("SELECT id, user_uuid::text FROM users WHERE user_uuid::text=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if row: return int(row[0]), row[1]

        cur.execute("SELECT id, user_uuid::text FROM users WHERE email=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if row: return int(row[0]), row[1]

        cur.execute("SELECT id, user_uuid::text FROM users WHERE phone=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if row: return int(row[0]), row[1]

        try:
            as_int = int(principal)
        except Exception:
            as_int = None
        if as_int is not None:
            cur.execute("SELECT id, user_uuid::text FROM users WHERE id=%s LIMIT 1", (as_int,))
            row = cur.fetchone()
            if row: return int(row[0]), row[1]

    raise HTTPException(status_code=401, detail="User principal could not be resolved")

class WalletOut(BaseModel):
    balance_cents: int
    currency: str
    updated_at: Optional[datetime] = None

class LedgerItem(BaseModel):
    id: str                    # DB returns UUID -> represent as text
    amount_cents: int
    currency: str
    kind: str                  # wallet_ledger.entry_type
    reference: Optional[str] = None
    idempotency_key: Optional[str] = None
    created_at: datetime

@router.get("/wallets/me", response_model=WalletOut)
def get_my_wallet(user=Depends(_lazy_current_user)):
    principal = _principal_from_user(user)
    if not principal:
        raise HTTPException(status_code=401, detail="No principal on user")

    with pg() as conn, conn.cursor() as cur:
        user_id_int, user_uuid = _resolve_user_ids(conn, principal)
        cur.execute("SELECT balance_cents, currency, updated_at FROM wallets WHERE user_id=%s", (user_id_int,))
        row = cur.fetchone()
        if not row:
            # zero wallet if not created yet
            return WalletOut(balance_cents=0, currency="ZAR", updated_at=None)
        return WalletOut(balance_cents=int(row[0]), currency=row[1], updated_at=row[2])

@router.get("/wallets/ledger/me", response_model=List[LedgerItem])
def get_my_ledger(limit: int = 50, user=Depends(_lazy_current_user)):
    limit = max(1, min(200, int(limit)))
    principal = _principal_from_user(user)
    if not principal:
        raise HTTPException(status_code=401, detail="No principal on user")

    with pg() as conn, conn.cursor() as cur:
        user_id_int, user_uuid = _resolve_user_ids(conn, principal)
        cur.execute("""
            SELECT id::text, amount_cents, currency, entry_type, reference, idempotency_key, created_at
              FROM wallet_ledger
             WHERE user_id=%s::uuid
             ORDER BY created_at DESC
             LIMIT %s
        """, (user_uuid, limit))
        rows = cur.fetchall() or []
        return [
            LedgerItem(
                id=r[0], amount_cents=int(r[1]), currency=r[2], kind=r[3],
                reference=r[4], idempotency_key=r[5], created_at=r[6]
            ) for r in rows
        ]
