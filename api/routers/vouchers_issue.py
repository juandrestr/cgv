from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
import os, json, base64, re
import psycopg
import psycopg.errors
import redis

# ---------- env knobs ----------
VOUCHER_CODE_LENGTH = int(os.getenv("VOUCHER_CODE_LENGTH", "16"))
VOUCHER_DEFAULT_CURRENCY = os.getenv("VOUCHER_DEFAULT_CURRENCY", "ZAR")
VOUCHER_DEFAULT_EXPIRY_DAYS = int(os.getenv("VOUCHER_DEFAULT_EXPIRY_DAYS", "183"))
VOUCHER_MAX_FACE_CENTS = int(os.getenv("VOUCHER_MAX_FACE_CENTS", "50000"))  # R500 default max
VOUCHER_ISSUE_RATE_PER_MIN = int(os.getenv("VOUCHER_ISSUE_RATE_PER_MIN", "30"))  # per issuer/min

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

_r = None
def _redis():
    global _r
    if _r is None:
        _r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _r

def pg():
    return psycopg.connect(DATABASE_URL, autocommit=False)

router = APIRouter(prefix="/vouchers", tags=["vouchers"])

# ---------- tiny JWT payload decode (signature assumed already verified upstream) ----------
_bearer = HTTPBearer(auto_error=True)

def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b = parts[1]
        pad = '=' * (-len(payload_b) % 4)
        data = base64.urlsafe_b64decode(payload_b + pad)
        return json.loads(data.decode("utf-8"))
    except Exception:
        return {}

def _get_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    payload = _decode_jwt_payload(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    uid_or_email = payload.get("sub") or payload.get("user_uuid") or payload.get("uid")
    role = (payload.get("role") or "").lower()
    if not uid_or_email:
        raise HTTPException(status_code=401, detail="No subject in token")
    return {"principal": uid_or_email, "role": role}

def _require_issuer(user: dict):
    # Allow admin/issuer/retailer for issuing
    if user["role"] not in {"admin", "issuer", "retailer"}:
        raise HTTPException(status_code=403, detail="Only issuers can create vouchers")

def _resolve_user_uuid(conn, principal: str) -> str:
    """
    Resolve a principal (uuid or email) to users.user_uuid
    """
    import re as _re
    if _re.fullmatch(r"[0-9a-fA-F-]{36}", principal):  # looks like UUID
        return principal
    with conn.cursor() as cur:
        cur.execute("SELECT user_uuid FROM users WHERE email=%s LIMIT 1", (principal,))
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=401, detail="Issuer not recognized")
        return str(row[0])

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _rate_limit_issue(issuer_uuid: str):
    """Simple per-issuer per-minute throttle with Redis."""
    r = _redis()
    bucket = _now_utc().strftime("%Y%m%d%H%M")
    key = f"rl:issue:{issuer_uuid}:{bucket}"
    pipe = r.pipeline()
    pipe.incr(key, 1)
    pipe.expire(key, 70)
    count, _ = pipe.execute()
    if count > VOUCHER_ISSUE_RATE_PER_MIN:
        raise HTTPException(status_code=429, detail="Issuance rate limit exceeded. Please retry in a minute.")

# ---------- models ----------
class IssueIn(BaseModel):
    face_value_cents: int = Field(gt=0)
    currency: str | None = Field(default=None)
    idempotency_key: str | None = Field(default=None, description="POS-level retry key")
    retailer_id: str | None = None
    outlet_id: str | None = None
    cashier_id: str | None = None
    till_ref: str | None = None
    provider: str | None = Field(default=None, description="kazang|bluelabel|...")
    provider_txn_id: str | None = None

class IssueOut(BaseModel):
    code: str
    currency: str
    face_value_cents: int
    expires_at: datetime
    print_lines: list[str]
    qr_text: str

# ---------- helpers ----------
_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
def _gen_code(n: int) -> str:
    import secrets
    return "".join(_ALNUM[secrets.randbelow(len(_ALNUM))] for _ in range(n))

def _fmt_money_zar(cents: int) -> str:
    rands = cents / 100.0
    return f"R{rands:,.2f}".replace(",", " ").replace(" ", "")

# ---------- route ----------
@router.post("/issue", response_model=IssueOut)
def issue_voucher(body: IssueIn, user=Depends(_get_user)):
    _require_issuer(user)

    face = int(body.face_value_cents)
    if face > VOUCHER_MAX_FACE_CENTS:
        raise HTTPException(status_code=400, detail=f"face_value_cents exceeds max {VOUCHER_MAX_FACE_CENTS}")

    currency = (body.currency or VOUCHER_DEFAULT_CURRENCY).upper()
    if not re.fullmatch(r"[A-Z]{3}", currency):
        raise HTTPException(status_code=400, detail="currency must be a 3-letter code like ZAR")

    expires_at = _now_utc() + timedelta(days=VOUCHER_DEFAULT_EXPIRY_DAYS)
    idem = body.idempotency_key.strip() if body.idempotency_key else None

    with pg() as conn:
        issuer_uuid = _resolve_user_uuid(conn, user['principal'])

        # Throttle per issuer/minute
        _rate_limit_issue(issuer_uuid)

        with conn.cursor() as cur:
            # Idempotency: if issuer+idem+face already issued an active code, return it
            if idem:
                cur.execute("""
                    SELECT v.id, vc.code, vc.currency, vc.amount_cents, v.expires_at
                    FROM vouchers v
                    JOIN voucher_codes vc ON vc.voucher_id = v.id
                    WHERE v.metadata ? 'idempotency_key'
                      AND v.metadata->>'idempotency_key' = %s
                      AND v.created_by = %s
                      AND v.face_value_cents = %s
                      AND vc.status = 'active'
                    ORDER BY vc.issued_at DESC
                    LIMIT 1
                """, (idem, issuer_uuid, face))
                row = cur.fetchone()
                if row:
                    _, code, curcy, amt, exp = row
                    return IssueOut(
                        code=code, currency=(curcy or currency), face_value_cents=int(amt), expires_at=exp,
                        print_lines=[
                            "Tiply Car-Guard Voucher",
                            f"Amount: {_fmt_money_zar(int(amt))}",
                            f"Code: {code}",
                            f"Expires: {exp.date().isoformat()}",
                        ],
                        qr_text=f"TIPLY:{code}",
                    )

            # Create vouchers row (unallocated)
            cur.execute("""
                INSERT INTO vouchers (currency, face_value_cents, expires_at, status, metadata, created_by)
                VALUES (%s, %s, %s, 'active',
                        jsonb_strip_nulls(jsonb_build_object(
                          'idempotency_key', %s::text,
                          'retailer_id', %s::text,
                          'outlet_id', %s::text,
                          'cashier_id', %s::text,
                          'till_ref', %s::text,
                          'provider', %s::text,
                          'provider_txn_id', %s::text
                        )),
                        %s)
                RETURNING id, expires_at
            """, (currency, face, expires_at,
                  idem,
                  body.retailer_id, body.outlet_id, body.cashier_id, body.till_ref,
                  body.provider, body.provider_txn_id,
                  issuer_uuid))
            v_id, exp = cur.fetchone()

            # Create voucher_codes entry with unique code
            attempts = 0
            while True:
                attempts += 1
                code = _gen_code(VOUCHER_CODE_LENGTH)
                try:
                    cur.execute("""
                        INSERT INTO voucher_codes (voucher_id, code, status, issued_at, issued_by, amount_cents, currency)
                        VALUES (%s, %s, 'active', now(), %s, %s, %s)
                        RETURNING code
                    """, (v_id, code, issuer_uuid, face, currency))
                    break
                except psycopg.errors.UniqueViolation:
                    if attempts > 5:
                        raise
                    conn.rollback()
                    cur = conn.cursor()

            # Try to write an audit event (non-fatal if it fails)
            try:
                # Your voucher_events schema: subject_type, subject_id, action, actor_user_id, payload
                cur.execute("""
                    INSERT INTO voucher_events (subject_type, subject_id, action, actor_user_id, payload)
                    VALUES (
                        'voucher', %s, 'issued', %s,
                        jsonb_strip_nulls(jsonb_build_object(
                          'idempotency_key', %s::text,
                          'retailer_id', %s::text,
                          'outlet_id', %s::text,
                          'cashier_id', %s::text,
                          'till_ref', %s::text,
                          'provider', %s::text,
                          'provider_txn_id', %s::text,
                          'face_value_cents', %s,
                          'currency', %s::text
                        ))
                    )
                """, (v_id, issuer_uuid,
                      idem,
                      body.retailer_id, body.outlet_id, body.cashier_id, body.till_ref,
                      body.provider, body.provider_txn_id,
                      face, currency))
            except Exception:
                pass

            conn.commit()

            return IssueOut(
                code=code, currency=currency, face_value_cents=face, expires_at=exp,
                print_lines=[
                    "Tiply Car-Guard Voucher",
                    f"Amount: {_fmt_money_zar(face)}",
                    f"Code: {code}",
                    f"Expires: {exp.date().isoformat()}",
                ],
                qr_text=f"TIPLY:{code}",
            )
