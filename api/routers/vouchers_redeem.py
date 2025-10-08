
from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import os, psycopg
import psycopg.errors

router = APIRouter()
_bearer = HTTPBearer(auto_error=True)

def _lazy_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    # Import at call-time to avoid circular import and reuse main's auth
    from main import get_current_user
    return get_current_user(creds)

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

def _principal_from_user(user):
    # Works for object-like or dict-like user payloads
    for k in ("user_uuid", "id", "sub", "email", "phone"):
        if hasattr(user, k):
            v = getattr(user, k)
            if v: return v
        try:
            v = user.get(k)  # dict-like
            if v: return v
        except Exception:
            pass
    return None

def _resolve_user_ids(conn, principal):
    """
    Resolve principal (uuid/email/phone/int) to BOTH:
      - users.id (int) for wallets.user_id (bigint)
      - users.user_uuid::text for *uuid* FKs (wallet_ledger.user_id, voucher_codes.redeemed_by_user_id)
    """
    principal = str(principal)
    with conn.cursor() as cur:
        # Try UUID path
        cur.execute("SELECT id, user_uuid::text FROM users WHERE user_uuid::text=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if row: return int(row[0]), row[1]

        # Email
        cur.execute("SELECT id, user_uuid::text FROM users WHERE email=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if row: return int(row[0]), row[1]

        # Phone
        cur.execute("SELECT id, user_uuid::text FROM users WHERE phone=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if row: return int(row[0]), row[1]

        # Numeric id (users.id)
        try:
            as_int = int(principal)
        except Exception:
            as_int = None
        if as_int is not None:
            cur.execute("SELECT id, user_uuid::text FROM users WHERE id=%s LIMIT 1", (as_int,))
            row = cur.fetchone()
            if row: return int(row[0]), row[1]

    raise HTTPException(status_code=401, detail="User principal could not be resolved")

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
    user = Depends(_lazy_current_user),
    Idempotency_Key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    if not Idempotency_Key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key header")

    code = (payload.code or "").strip().upper()
    if not code:
        raise HTTPException(status_code=400, detail="Invalid code")

    principal = _principal_from_user(user)
    if not principal:
        raise HTTPException(status_code=401, detail="No principal on user")

    now = datetime.now(timezone.utc)

    with pg() as conn:
        try:
            with conn.cursor() as cur:
                user_id_int, user_uuid = _resolve_user_ids(conn, principal)  # <- BOTH ids

                # Lock voucher row
                cur.execute("""
                    SELECT id, code, amount_cents, currency, state, expires_at, redeemed_at
                      FROM voucher_codes
                     WHERE code = %s
                     FOR UPDATE
                """, (code,))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Voucher not found")
                vid, vcode, amount_cents, currency, state, expires_at, redeemed_at = row

                if expires_at and now > expires_at:
                    raise HTTPException(status_code=410, detail="Voucher expired")
                if amount_cents is None or amount_cents <= 0:
                    raise HTTPException(status_code=422, detail="Voucher has zero value")

                # Ensure wallet exists (wallets.user_id is BIGINT -> users.id)
                cur.execute("""
                    INSERT INTO wallets(user_id, balance_cents, currency, updated_at)
                    VALUES (%s, 0, %s, now())
                    ON CONFLICT (user_id) DO NOTHING
                """, (user_id_int, currency))

                # If already redeemed, don't credit again
                if state != 'ISSUED':
                    cur2 = conn.cursor()
                    cur2.execute("SELECT balance_cents FROM wallets WHERE user_id=%s", (user_id_int,))
                    wb = cur2.fetchone()
                    wallet_balance = wb[0] if wb else 0
                    return RedeemOut(
                        code=vcode,
                        credited_cents=amount_cents,
                        currency=currency,
                        wallet_balance_cents=wallet_balance,
                        state=state,
                        redeemed_at=redeemed_at or now
                    )


                # Idempotent ledger insert (wallet_ledger.user_id is UUID -> users.user_uuid)
                try:
                    cur.execute("""
                        INSERT INTO wallet_ledger(user_id, amount_cents, currency, entry_type, reference, idempotency_key)
                        VALUES (%s::uuid, %s, %s, 'credit', %s, %s)
                        RETURNING id
                    """, (user_uuid, amount_cents, currency, vcode, Idempotency_Key))

                    # Apply to balance (wallets.user_id BIGINT)
                    cur.execute("""
                        UPDATE wallets
                           SET balance_cents = balance_cents + %s,
                               updated_at = now()
                         WHERE user_id = %s
                         RETURNING balance_cents
                    """, (amount_cents, user_id_int))
                    wallet_balance = cur.fetchone()[0]

                    # Mark voucher redeemed on first success (redeemed_by_user_id UUID)
                    if state == 'ISSUED':
                        cur.execute("""
                            UPDATE voucher_codes
                               SET state='REDEEMED',
                                   redeemed_at=now(),
                                   redeemed_by_user_id=%s::uuid
                             WHERE id=%s
                        """, (user_uuid, vid))
                        cur.execute("""
                            INSERT INTO voucher_events(action, idempotency_key, subject_type, subject_id, payload)
                            VALUES ('redeemed', %s, 'voucher', %s, json_build_object('code', %s, 'user_uuid', %s))
                        """, (Idempotency_Key, vid, vcode, user_uuid))

                except psycopg.errors.UniqueViolation:
                    # Safe replay of the same Idempotency-Key
                    conn.rollback()
                    with conn.cursor() as c2:
                        c2.execute("SELECT balance_cents FROM wallets WHERE user_id=%s", (user_id_int,))
                        wb = c2.fetchone()
                        wallet_balance = wb[0] if wb else 0
                        c2.execute("SELECT state, redeemed_at FROM voucher_codes WHERE id=%s", (vid,))
                        st, r_at = c2.fetchone()
                        return RedeemOut(
                            code=vcode,
                            credited_cents=amount_cents,
                            currency=currency,
                            wallet_balance_cents=wallet_balance,
                            state=st,
                            redeemed_at=r_at or now
                        )

                # Success
                cur.execute("SELECT state, redeemed_at FROM voucher_codes WHERE id=%s", (vid,))
                st, r_at = cur.fetchone()
                return RedeemOut(
                    code=vcode,
                    credited_cents=amount_cents,
                    currency=currency,
                    wallet_balance_cents=wallet_balance,
                    state=st,
                    redeemed_at=r_at or now
                )
        except HTTPException:
            raise
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=500, detail=f"redeem failed: {e}")
        finally:
            conn.commit()
