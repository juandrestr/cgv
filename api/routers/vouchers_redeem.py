from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
import os, psycopg
from psycopg import errors as pg_errors

from rate_limit import throttle  # /app/rate_limit.py

router = APIRouter()
_bearer = HTTPBearer(auto_error=True)

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

def _current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    from main import get_current_user
    return get_current_user(creds)

class RedeemIn(BaseModel):
    code: str

@router.post("/vouchers/redeem/self")
def redeem_self(
    payload: RedeemIn,
    user = Depends(_current_user),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key")

    # Prefer user_uuid (per your auth patch), fall back to other names
    uid = (
        getattr(user, "user_uuid", None)
        or getattr(user, "user_id", None)
        or getattr(user, "id", None)
        or getattr(user, "sub", None)
    )
    if not uid:
        raise HTTPException(status_code=401, detail="No user")

    # Per-user throttle
    try:
        throttle(uid, "redeem", limit=5, window_sec=60)
    except RuntimeError:
        raise HTTPException(status_code=429, detail="Too many redeem attempts, slow down")

    now = datetime.now(timezone.utc)

    with pg() as conn:
        try:
            with conn.cursor() as cur:
                # 0) Idempotency replay (user uuid key)
                cur.execute(
                    """
                    select code, credited_cents, currency, wallet_balance_cents, state, redeemed_at
                    from voucher_redeem_receipts
                    where user_id = %s::uuid and idem_key = %s
                    limit 1
                    """,
                    (uid, idempotency_key),
                )
                row = cur.fetchone()
                if row:
                    code, credited, currency, wallet_bal, state, redeemed_at = row
                    return {
                        "code": code,
                        "credited_cents": credited,
                        "currency": currency,
                        "wallet_balance_cents": wallet_bal,
                        "state": state,
                        "redeemed_at": redeemed_at.isoformat().replace("+00:00", "Z") if redeemed_at else None,
                    }

                # 1) Load + lock the voucher row via code -> voucher_id
                #    Your schema: voucher_codes(code, voucher_id) -> vouchers(id)
                cur.execute(
                    """
                    select v.id, v.redeemed_at, v.face_value_cents, v.currency
                    from vouchers v
                    join voucher_codes c on c.voucher_id = v.id
                    where c.code = %s
                    for update of v
                    """,
                    (payload.code,),
                )
                v = cur.fetchone()
                if not v:
                    raise HTTPException(status_code=404, detail="Voucher not found")
                voucher_id, redeemed_at, face_value_cents, currency = v
                if redeemed_at is not None:
                    raise HTTPException(status_code=409, detail="Voucher already redeemed")

                # 2) Mark as redeemed
                cur.execute(
                    """
                    update vouchers
                    set redeemed_by = %s::uuid, redeemed_at = %s
                    where id = %s
                    """,
                    (uid, now, voucher_id),
                )

                # 3) Credit wallet:
                # wallets.user_id is BIGINT; translate from users.user_uuid -> users.id
                cur.execute(
                    """
                    update wallets w
                    set balance_cents = w.balance_cents + %s
                    from users u
                    where u.user_uuid = %s::uuid
                      and w.user_id = u.id
                    returning w.balance_cents
                    """,
                    (face_value_cents, uid),
                )
                r = cur.fetchone()
                if not r:
                    raise HTTPException(status_code=500, detail="Wallet not found for user")
                new_balance = r[0]

                # 4) Ledger (+) — your table uses entry_type with a CHECK ('credit','debit','payout')
                cur.execute(
                    """
                    insert into wallet_ledger
                      (user_id, entry_type, amount_cents, currency, reference, idempotency_key)
                    values (%s::uuid, 'credit', %s, %s, %s, %s)
                    """,
                    (uid, face_value_cents, currency, payload.code, idempotency_key),
                )

                # 5) Idempotent receipt (PK on (user_id, idem_key))
                cur.execute(
                    """
                    insert into voucher_redeem_receipts
                      (user_id, idem_key, code, credited_cents, currency, wallet_balance_cents, state, redeemed_at)
                    values (%s::uuid, %s, %s, %s, %s, %s, 'REDEEMED', %s)
                    """,
                    (uid, idempotency_key, payload.code, face_value_cents, currency, new_balance, now),
                )

            conn.commit()
            return {
                "code": payload.code,
                "credited_cents": face_value_cents,
                "currency": currency,
                "wallet_balance_cents": new_balance,
                "state": "REDEEMED",
                "redeemed_at": now.isoformat().replace("+00:00", "Z"),
            }

        except pg_errors.UniqueViolation:
            conn.rollback()
            # Replay the prior receipt
            with pg() as c2, c2.cursor() as cur2:
                cur2.execute(
                    """
                    select code, credited_cents, currency, wallet_balance_cents, state, redeemed_at
                    from voucher_redeem_receipts
                    where user_id = %s::uuid and idem_key = %s
                    limit 1
                    """,
                    (uid, idempotency_key),
                )
                row = cur2.fetchone()
                if row:
                    code, credited, currency, wallet_bal, state, redeemed_at = row
                    return {
                        "code": code,
                        "credited_cents": credited,
                        "currency": currency,
                        "wallet_balance_cents": wallet_bal,
                        "state": state,
                        "redeemed_at": redeemed_at.isoformat().replace("+00:00","Z") if redeemed_at else None,
                    }
            raise
        except HTTPException:
            conn.rollback(); raise
        except Exception:
            conn.rollback(); raise
