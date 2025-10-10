from fastapi import APIRouter, Header, HTTPException, Body, Request
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import os, hmac, hashlib, psycopg, json, secrets, string, random

router = APIRouter()

def pg():
    return psycopg.connect(os.getenv("DATABASE_URL"), autocommit=False)

class IssueIn(BaseModel):
    face_value_cents: int = Field(..., gt=0)
    currency: str = Field("ZAR", min_length=1, max_length=8)
    expires_in_days: int = Field(180, ge=1, le=365)
    metadata: dict = Field(default_factory=dict)

class IssueOut(BaseModel):
    code: str
    currency: str
    face_value_cents: int
    expires_at: Optional[str]
    print_lines: List[str]
    qr_text: str

def _hmac_ok(secret: str, raw: bytes, sig_hex: str) -> bool:
    try:
        expect = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        return secrets.compare_digest(expect, sig_hex.lower())
    except Exception:
        return False

def _rand_code(n=16):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(random.choices(alphabet, k=n))

@router.post("/merchant/vouchers/issue", response_model=IssueOut)
async def merchant_issue(
    request: Request,
    payload: IssueIn = Body(...),
    merchant_id: str = Header(..., alias="X-Merchant-Id"),
    signature: str = Header(..., alias="X-Signature"),
    idem: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    secret = os.getenv("MERCHANT_HMAC_SECRET")
    if not secret:
        raise HTTPException(500, "MERCHANT_HMAC_SECRET not configured")
    if not idem:
        raise HTTPException(400, "Missing Idempotency-Key")

    raw_body = await request.body()
    if not _hmac_ok(secret, raw_body, signature):
        raise HTTPException(401, "Invalid signature")

    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=payload.expires_in_days)) if payload.expires_in_days else None

    req_json = {
        "merchant_id": merchant_id,
        "idem_key": idem,
        "payload": payload.dict(),
        "received_at": now.isoformat(),
    }

    resp_json = None
    status_code = 500

    with pg() as conn:
        try:
            with conn.cursor() as cur:
                # Idempotency: return the existing issue if present
                cur.execute(
                    """SELECT code,currency,face_value_cents,expires_at
                       FROM merchant_issue_receipts
                       WHERE merchant_id=%s AND idem_key=%s""",
                    (merchant_id, idem),
                )
                row = cur.fetchone()
                if row:
                    code, currency, face_value_cents, exp = row
                    out = IssueOut(
                        code=code,
                        currency=currency,
                        face_value_cents=face_value_cents,
                        expires_at=exp.isoformat() if exp else None,
                        print_lines=[
                            f"Voucher code: {code}",
                            f"Amount: {face_value_cents/100:.2f} {currency}",
                            f"Expires: {exp.isoformat() if exp else 'N/A'}",
                        ],
                        qr_text=code,
                    )
                    resp_json = json.dumps(out.dict())
                    status_code = 200
                    return out

                # Insert voucher (created_by required by schema)
                cur.execute(
                    """INSERT INTO vouchers (currency, face_value_cents, expires_at, status, metadata, created_by)
                       VALUES (%s, %s, %s, 'active', %s, gen_random_uuid())
                       RETURNING id""",
                    (payload.currency, payload.face_value_cents, expires_at, json.dumps({"idempotency_key": idem, **payload.metadata})),
                )
                (voucher_id,) = cur.fetchone()

                # Insert code (issued_by required by schema)
                code = _rand_code(16)
                cur.execute(
                    """INSERT INTO voucher_codes
                       (voucher_id, code, status, issued_at, issued_by, amount_cents, currency, expires_at, state)
                       VALUES (%s, %s, 'active', now(), gen_random_uuid(), %s, %s, %s, 'ISSUED')
                       RETURNING code""",
                    (voucher_id, code, payload.face_value_cents, payload.currency, expires_at),
                )
                (code,) = cur.fetchone()

                # Save merchant receipt (idempotency key)
                cur.execute(
                    """INSERT INTO merchant_issue_receipts
                       (merchant_id, idem_key, code, currency, face_value_cents, expires_at)
                       VALUES (%s, %s, %s, %s, %s, %s)
                       ON CONFLICT (merchant_id, idem_key) DO NOTHING""",
                    (merchant_id, idem, code, payload.currency, payload.face_value_cents, expires_at),
                )

                out = IssueOut(
                    code=code,
                    currency=payload.currency,
                    face_value_cents=payload.face_value_cents,
                    expires_at=expires_at.isoformat() if expires_at else None,
                    print_lines=[
                        f"Voucher code: {code}",
                        f"Amount: {payload.face_value_cents/100:.2f} {payload.currency}",
                        f"Expires: {expires_at.isoformat() if expires_at else 'N/A'}",
                    ],
                    qr_text=code,
                )
                resp_json = json.dumps(out.dict())
                status_code = 200
                conn.commit()
                return out

        except psycopg.Error as e:
            conn.rollback()
            raise HTTPException(500, f"DB error: {e.pgerror or str(e)}") from e
        finally:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO merchant_issue_audit
                           (merchant_id, idem_key, request_json, response_json, status_code, created_at)
                           VALUES (%s, %s, %s::jsonb, %s::jsonb, %s, now())""",
                        (merchant_id, idem, json.dumps(req_json), resp_json, status_code),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
# -----------------------
# LOOKUP + REDEEM (M11)
# -----------------------
class LookupOut(BaseModel):
    code: str
    currency: Optional[str]
    face_value_cents: int
    state: str
    status: str
    issued_at: Optional[str]
    expires_at: Optional[str]

@router.get("/merchant/vouchers/{code}", response_model=LookupOut)
async def merchant_lookup(code: str):
    with pg() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT
              vc.code,
              COALESCE(vc.currency, v.currency) AS currency,
              v.face_value_cents,
              vc.state,
              vc.status,
              vc.issued_at,
              vc.expires_at
            FROM voucher_codes vc
            JOIN vouchers v ON v.id = vc.voucher_id
            WHERE vc.code = %s
            LIMIT 1
        """, (code,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Code not found")

        return LookupOut(
            code=row[0],
            currency=row[1],
            face_value_cents=row[2],
            state=row[3],
            status=row[4],
            issued_at=row[5].isoformat() if row[5] else None,
            expires_at=row[6].isoformat() if row[6] else None,
        )

class RedeemIn(BaseModel):
    code: str

class RedeemOut(BaseModel):
    code: str
    state: str
    status: str
    redeemed_at: Optional[str]

@router.post("/merchant/vouchers/redeem", response_model=RedeemOut)
async def merchant_redeem(
    request: Request,
    payload: RedeemIn = Body(...),
    merchant_id: str = Header(..., alias="X-Merchant-Id"),
    signature: str = Header(..., alias="X-Signature"),
    idem: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # HMAC + idem checks
    secret = os.getenv("MERCHANT_HMAC_SECRET")
    if not secret:
        raise HTTPException(500, "MERCHANT_HMAC_SECRET not configured")
    if not idem:
        raise HTTPException(400, "Missing Idempotency-Key")

    raw_body = await request.body()
    if not _hmac_ok(secret, raw_body, signature):
        raise HTTPException(401, "Invalid signature")

    now = datetime.now(timezone.utc)

    # Fast path: idempotency hit?
    try:
        with pg() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT response_json
                FROM merchant_redeem_receipts
                WHERE merchant_id = %s AND idem_key = %s
                LIMIT 1
                """,
                (merchant_id, idem),
            )
            row = cur.fetchone()
            if row:
                resp = row[0]
                # Normalize to dict if driver returns a string
                if isinstance(resp, str):
                    import json as _json
                    resp = _json.loads(resp)
                # audit (deduped by unique partial index)
                cur.execute(
                    """
                    INSERT INTO merchant_issue_audit
                      (merchant_id, idem_key, request_json, response_json, status_code)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (merchant_id, idem,
                     json.dumps({"code": payload.code}),
                     json.dumps(resp),
                     200),
                )
                conn.commit()
                return RedeemOut(**resp)
    except Exception:
        # don't fail due to read/audit hiccups; fall through
        pass

    # Normal redeem flow
    try:
        with pg() as conn, conn.cursor() as cur:
            # Lock code row to prevent race double-spend
            cur.execute(
                """
                SELECT vc.id, vc.voucher_id, vc.state, vc.status, vc.expires_at
                FROM voucher_codes vc
                WHERE vc.code = %s
                FOR UPDATE
                """,
                (payload.code,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Code not found")

            code_id, voucher_id, state, status, expires_at = row

            if state == "REDEEMED":
                raise HTTPException(409, f"Code not redeemable (state={state})")
            if expires_at and expires_at < now:
                raise HTTPException(409, "Code expired")

            # Mark redeemed
            cur.execute(
                """
                UPDATE voucher_codes
                   SET state = 'REDEEMED',
                       status = 'spent',
                       redeemed_at = %s
                 WHERE id = %s
                """,
                (now, code_id),
            )
            cur.execute(
                """
                UPDATE vouchers
                   SET redeemed_at = %s
                 WHERE id = %s AND redeemed_at IS NULL
                """,
                (now, voucher_id),
            )

            response = {
                "code": payload.code,
                "state": "REDEEMED",
                "status": "spent",
                "redeemed_at": now.isoformat(),
            }

            # Idempotent success receipt
            cur.execute(
                """
                INSERT INTO merchant_redeem_receipts
                  (merchant_id, idem_key, code, redeemed_at, response_json)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (merchant_id, idem_key) DO NOTHING
                """,
                (merchant_id, idem, payload.code, now, json.dumps(response)),
            )

            # Audit success (200)
            cur.execute(
                """
                INSERT INTO merchant_issue_audit
                  (merchant_id, idem_key, request_json, response_json, status_code)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (merchant_id, idem,
                 json.dumps({"code": payload.code}),
                 json.dumps(response),
                 200),
            )

            conn.commit()
            return RedeemOut(**response)

    except HTTPException:
        raise
    except Exception as e:
        # Audit failure
        try:
            with pg() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO merchant_issue_audit
                      (merchant_id, idem_key, request_json, response_json, status_code)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (merchant_id, idem,
                     json.dumps({"code": payload.code}),
                     json.dumps({"error": str(e)}),
                     500),
                )
                conn.commit()
        except Exception:
            pass
        raise HTTPException(500, f"Redeem failed: {e}")
