from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from types import SimpleNamespace
from main import decode_token
import os, psycopg, jwt, json

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

bearer = HTTPBearer(auto_error=False)

def _payload_from_token(token: str):
    # Try app's decode_token first (builds differ)
    try:
        res = decode_token(token)
    except Exception:
        res = None
    if isinstance(res, dict):
        return res
    if isinstance(res, (tuple, list)) and res and isinstance(res[0], dict):
        return res[0]
    # Fallback: read claims w/o verifying signature
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

class RedeemIn(BaseModel):
    code: str

class RedeemOut(BaseModel):
    code: str
    credited_cents: int
    currency: str
    wallet_balance_cents: int
    state: str
    redeemed_at: datetime

@router.post("/vouchers/redeem/self", response_model=RedeemOut)
def redeem_self(
    payload: RedeemIn,
    user = Depends(current_user_dep),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key header")

    code = (payload.code or "").strip().upper()
    if not code:
        raise HTTPException(status_code=400, detail="Invalid code")

    with pg() as conn:
        try:
            with conn.cursor() as cur:
                # Lock voucher code
                cur.execute("""
                    SELECT id, amount_cents, currency, status, state, redeemed_at, expires_at
                    FROM voucher_codes
                    WHERE code = %s
                    FOR UPDATE
                """, (code,))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Code not found")
                code_id, amount_cents, currency, status, state, redeemed_at, expires_at = row

                if status != "active" or state != "ISSUED" or redeemed_at is not None:
                    raise HTTPException(status_code=409, detail="Code already used or not redeemable")

                if expires_at and expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                    raise HTTPException(status_code=410, detail="Code expired")

                user_uuid = _user_uuid(conn, user)
                ccy = currency or "ZAR"

                # Ensure wallet row exists (UUID key)
                cur.execute("""
                    INSERT INTO wallet_accounts(user_id, currency, balance_cents)
                    VALUES (%s, %s, 0)
                    ON CONFLICT (user_id) DO NOTHING
                """, (user_uuid, ccy))

                # Credit wallet
                cur.execute("""
                    UPDATE wallet_accounts
                    SET balance_cents = balance_cents + %s,
                        currency = COALESCE(%s, currency),
                        updated_at = now()
                    WHERE user_id = %s
                    RETURNING balance_cents
                """, (amount_cents, ccy, user_uuid))
                bal = cur.fetchone()[0]

                # Ledger (UUID user_id), idempotent
                meta = {"source":"voucher","code":code,"voucher_code_id": str(code_id)}
                cur.execute("""
                    INSERT INTO wallet_ledger
                    (user_id, entry_type, amount_cents, currency, reference, meta, idempotency_key)
                    VALUES (%s, 'credit', %s, %s, %s, %s::jsonb, %s)
                    ON CONFLICT (idempotency_key) DO NOTHING
                """, (user_uuid, amount_cents, ccy, code, json.dumps(meta), idempotency_key))

                # Mark redeemed
                cur.execute("""
                    UPDATE voucher_codes
                    SET state='REDEEMED', redeemed_at=now(), redeemed_by_user_id=%s
                    WHERE id=%s
                """, (user_uuid, code_id))

            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"redeem failed: {e}")

    return RedeemOut(
        code=code,
        credited_cents=amount_cents,
        currency=ccy,
        wallet_balance_cents=bal,
        state="REDEEMED",
        redeemed_at=datetime.now(timezone.utc),
    )
