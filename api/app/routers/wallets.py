from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from types import SimpleNamespace
from main import decode_token
import os, psycopg, jwt

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

bearer = HTTPBearer(auto_error=False)

def _payload_from_token(token: str):
    try:
        res = decode_token(token)
    except Exception:
        res = None
    if isinstance(res, dict):
        return res
    if isinstance(res, (tuple, list)) and res and isinstance(res[0], dict):
        return res[0]
    try:
        return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    except Exception:
        return None

def current_user_dep(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds or not getattr(creds, "credentials", None):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    payload = _payload_from_token(creds.credentials)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="Invalid token")
    expected = os.getenv("JWT_ISSUER", "cgv-api")
    if payload.get("iss") != expected:
        raise HTTPException(status_code=401, detail="Invalid token")
    return SimpleNamespace(id=payload.get("sub"), email=payload.get("email"), role=payload.get("role"))

def _user_uuid(conn, user):
    uid = (user.get('id') if isinstance(user, dict) else getattr(user, 'id', None))
    if not uid:
        raise HTTPException(status_code=401, detail="No subject in token")
    with conn.cursor() as cur:
        cur.execute("SELECT user_uuid FROM users WHERE user_uuid=%s AND is_active=TRUE", (uid,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="User not found or disabled")
        return row[0]

router = APIRouter()

@router.get("/_whoami")
def _whoami(user=Depends(current_user_dep)):
    return {"id": user.id, "role": user.role}

class WalletOut(BaseModel):
    balance_cents: int
    currency: str
    updated_at: datetime

class LedgerItem(BaseModel):
    id: str
    amount_cents: int
    currency: str
    kind: str
    reference: Optional[str] = None
    idempotency_key: Optional[str] = None
    created_at: datetime

@router.get("/wallets/me", response_model=WalletOut)
def get_my_wallet(user=Depends(current_user_dep)):
    with pg() as conn, conn.cursor() as cur:
        user_uuid = _user_uuid(conn, user)
        cur.execute("SELECT balance_cents, currency, updated_at FROM wallet_accounts WHERE user_id=%s", (user_uuid,))
        row = cur.fetchone()
        if not row:
            cur.execute("""
                INSERT INTO wallet_accounts(user_id, currency, balance_cents)
                VALUES (%s, 'ZAR', 0)
                ON CONFLICT (user_id) DO NOTHING
            """, (user_uuid,))
            conn.commit()
            return WalletOut(balance_cents=0, currency="ZAR", updated_at=datetime.utcnow())
        return WalletOut(balance_cents=row[0], currency=row[1], updated_at=row[2])

@router.get("/wallets/ledger/me", response_model=List[LedgerItem])
def get_my_ledger(limit: int = 50, user=Depends(current_user_dep)):
    with pg() as conn, conn.cursor() as cur:
        user_uuid = _user_uuid(conn, user)
        cur.execute("""
            SELECT id, amount_cents, currency, entry_type, reference, idempotency_key, created_at
            FROM wallet_ledger
            WHERE user_id=%s
            ORDER BY created_at DESC
            LIMIT %s
        """, (user_uuid, max(1, min(limit, 200))))
        rows = cur.fetchall() or []
        return [
            LedgerItem(
                id=str(r[0]), amount_cents=r[1], currency=r[2],
                kind=r[3], reference=r[4], idempotency_key=r[5], created_at=r[6]
            )
            for r in rows
        ]
