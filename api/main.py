from routers import vouchers_issue
import rbac_m7
from fastapi.routing import APIRoute
import psycopg
import json
from fastapi import FastAPI, Depends, HTTPException, status, Request
import os, time, uuid
from jose import jwt, JWTError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
import os
import redis

from db import get_conn
from auth import hash_password, verify_password, create_access_token, decode_token

app = FastAPI()
app.include_router(vouchers_issue.router)
from routers.vouchers import router as vouchers_router
app.include_router(vouchers_router)




rbac_m7.setup(app)
# =========================
# M7 RBAC (safe injection)
# =========================
try:
    get_current_user  # provided by M1–M6
except NameError:
    def get_current_user():
        raise RuntimeError("get_current_user missing — ensure M1–M6 are applied")

def _m7_db():
    url = os.getenv("DATABASE_URL") or "postgresql://cgv:cgv@db:5432/cgv"
    return psycopg.connect(url)

def _m7_is_admin(email: str) -> bool:
    if not email: return False
    with _m7_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT is_admin FROM users WHERE user_uuid=%s LIMIT 1;", (email,))
        row = cur.fetchone()
        return bool(row and row[0])

def require_admin(user=Depends(get_current_user)):
    email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    if not email or not _m7_is_admin(email):
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    return user



def user_ping(user=Depends(get_current_user)):
    email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    return {"ok": True, "user": email or "unknown"}
# === M6: JWT session settings ===
JWT_SECRET  = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG     = "HS256"
JWT_ISSUER  = os.getenv("JWT_ISSUER", "cgv")
ACCESS_TTL  = int(os.getenv("JWT_ACCESS_TTL", "900"))       # 15 minutes
REFRESH_TTL = int(os.getenv("JWT_REFRESH_TTL", "604800"))   # 7 days

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.get("/version")
def version():
    return {
        "commit": os.getenv("GIT_COMMIT", "unknown"),
        "version": os.getenv("APP_VERSION", "0.0.1"),
        "env": os.getenv("ENVIRONMENT", "dev"),
    }

# ---------- Rate limit config ----------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

LOGIN_MAX_ATTEMPTS    = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS  = int(os.getenv("LOGIN_WINDOW_SECONDS", "600"))   # attempt counter TTL
LOGIN_LOCK_SECONDS    = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))     # lock duration

def _keys(email: str, ip: str):
    email = (email or "").lower()
    ip = ip or "unknown"
    return {
        "attempts_email": f"login:attempts:email:{email}",
        "attempts_ip":    f"login:attempts:ip:{ip}",
        "lock_email":     f"login:lock:email:{email}",
        "lock_ip":        f"login:lock:ip:{ip}",
    }

def is_locked(email: str, ip: str):
    k = _keys(email, ip)
    ttl_email = r.ttl(k["lock_email"])
    ttl_ip    = r.ttl(k["lock_ip"])
    locked = (ttl_email and ttl_email > 0) or (ttl_ip and ttl_ip > 0)
    ttl = 0
    for t in (ttl_email, ttl_ip):
        if t and t > 0:
            ttl = t
            break
    return locked, ttl

def register_failure(email: str, ip: str):
    k = _keys(email, ip)
    pipe = r.pipeline()
    pipe.incr(k["attempts_email"])
    pipe.expire(k["attempts_email"], LOGIN_WINDOW_SECONDS)
    pipe.incr(k["attempts_ip"])
    pipe.expire(k["attempts_ip"], LOGIN_WINDOW_SECONDS)
    cnt_email, _, cnt_ip, _ = pipe.execute()
    if cnt_email >= LOGIN_MAX_ATTEMPTS or cnt_ip >= LOGIN_MAX_ATTEMPTS:
        r.setex(k["lock_email"], LOGIN_LOCK_SECONDS, "1")
        r.setex(k["lock_ip"], LOGIN_LOCK_SECONDS, "1")
        return True
    return False

def clear_counters(email: str, ip: str):
    k = _keys(email, ip)
    r.delete(k["attempts_email"], k["attempts_ip"], k["lock_email"], k["lock_ip"])

# ---------- Schemas ----------
class LoginIn(BaseModel):
    email: EmailStr
    password: str

class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    role: str = "user"

class MeOut(BaseModel):
    email: EmailStr
    role: str

# ---------- Auth dependencies ----------
bearer = HTTPBearer(auto_error=False)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> MeOut:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = creds.credentials
    try:
        email, role = decode_token(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    with get_conn() as conn:
        row = conn.execute("SELECT email, role, is_active FROM users WHERE user_uuid=%s", (email,)).fetchone()
    if not row or not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User disabled")
    return MeOut(email=row["email"], role=row["role"])

def require_admin(user: MeOut = Depends(get_current_user)) -> MeOut:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return user

# ---------- Admin bootstrap (guarded) ----------
@app.post("/auth/bootstrap-admin")
def bootstrap_admin():
    if os.getenv("ALLOW_BOOTSTRAP", "false").lower() not in ("1","true","yes"):
        raise HTTPException(status_code=403, detail="Bootstrap disabled")
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_pass  = os.getenv("ADMIN_PASSWORD")
    if not admin_email or not admin_pass:
        raise HTTPException(status_code=400, detail="Set ADMIN_EMAIL and ADMIN_PASSWORD in env")
    with get_conn() as conn, conn.cursor() as cur:
        row = conn.execute("SELECT id FROM users WHERE user_uuid=%s", (admin_email,)).fetchone()
        if row:
            return {"status": "exists", "email": admin_email}
        cur.execute(
            "INSERT INTO users (email, password_hash, role, is_active) VALUES (%s,%s,'admin',TRUE)",
            (admin_email, hash_password(admin_pass))
        )
        conn.commit()
    return {"status": "created", "email": admin_email}

# ---------- Login with rate-limit ----------
@app.post("/auth/login")
def login(body: LoginIn, request: Request):
    ip = request.client.host if request and request.client else "unknown"

    locked, ttl = is_locked(body.email, ip)
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {ttl} seconds."
        )

    with get_conn() as conn:
        row = conn.execute(
            "SELECT email, password_hash, role, is_active FROM users WHERE user_uuid=%s",
            (body.email,)
        ).fetchone()

    if not row or not row["is_active"] or not verify_password(body.password, row["password_hash"]):
        just_locked = register_failure(body.email, ip)
        if just_locked:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed attempts. Locked for {LOGIN_LOCK_SECONDS} seconds."
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    clear_counters(body.email, ip)
    token = create_access_token(str(row["user_uuid"]), row["role"])

    # M6: issue refresh + store jti and return pair
    jti_new = str(uuid.uuid4())
    uid = body.email if hasattr(body, 'email') else 'user1@example.com'
    refresh = _make_jwt(uid, REFRESH_TTL, scope='refresh', jti=jti_new)
    try:
        store_refresh_jti(r, uid, jti_new, {'issued_at': _now()})
    except Exception:
        pass
    return {'access_token': token, 'refresh_token': refresh, 'token_type': 'bearer'}

@app.post("/auth/register", dependencies=[Depends(require_admin)])
def register(body: RegisterIn, admin: MeOut = Depends(require_admin)):
    if body.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")
    with get_conn() as conn, conn.cursor() as cur:
        exists = conn.execute("SELECT 1 FROM users WHERE user_uuid=%s", (body.email,)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Email already exists")
        cur.execute(
            "INSERT INTO users (email, password_hash, role, is_active) VALUES (%s,%s,%s,TRUE)",
            (body.email, hash_password(body.password), body.role)
        )
        conn.commit()
    return {"status": "created", "email": str(body.email), "role": body.role}

# ---------- Who am I ----------
@app.get("/me", response_model=MeOut)
def me(user: MeOut = Depends(get_current_user)):
    return user

# ---------- Admin unlock (clears email + current caller IP) ----------
@app.post("/auth/unlock")
def unlock(email: EmailStr, request: Request, admin: MeOut = Depends(require_admin)):
    ip = request.client.host if request and request.client else None
    # always clear email counters/locks
    r.delete(f"login:attempts:email:{str(email).lower()}",
             f"login:lock:email:{str(email).lower()}")
    # optionally clear this IP too (useful in dev)
    if ip:
        r.delete(f"login:attempts:ip:{ip}", f"login:lock:ip:{ip}")
    return {"status": "unlocked", "email": str(email), "cleared_ip": ip}


# === M6: Models ===
from pydantic import BaseModel

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshIn(BaseModel):
    refresh_token: str

class LogoutIn(BaseModel):
    refresh_token: str

# === M6: Helpers ===
def _now() -> int:
    return int(time.time())

def _make_jwt(sub: str, ttl: int, *, scope: str, jti: str | None = None) -> str:
    iat = _now()
    payload = {
        "iss": JWT_ISSUER,
        "sub": sub,
        "iat": iat,
        "nbf": iat,
        "exp": iat + ttl,
        "scope": scope,
        "jti": jti or str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def _verify_jwt(token: str, *, scope: str):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], options={"verify_aud": False})
    except JWTError:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="invalid_token")
    if data.get("iss") != JWT_ISSUER:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="bad_issuer")
    if data.get("scope") != scope:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="bad_scope")
    return data

def _refresh_key(user_id: str, jti: str) -> str:
    return f"refresh:{user_id}:{jti}"

def _refresh_index(user_id: str) -> str:
    return f"refresh:index:{user_id}"

def store_refresh_jti(r, user_id: str, jti: str, meta: dict):
    r.setex(_refresh_key(user_id, jti), REFRESH_TTL, json.dumps(meta))
    r.sadd(_refresh_index(user_id), jti)

def delete_refresh_jti(r, user_id: str, jti: str):
    r.delete(_refresh_key(user_id, jti))
    r.srem(_refresh_index(user_id), jti)

def refresh_jti_exists(r, user_id: str, jti: str) -> bool:
    return r.exists(_refresh_key(user_id, jti)) == 1


# If your login already returns JSON via FastAPI, but without refresh_token, we monkey-patch FastAPI route below.
try:
    original_login = login
    @app.post("/auth/login", name="login_m6_wrapper")
    def login_m6_wrapper(*args, **kwargs):
        res = original_login(*args, **kwargs)
        # Try to get a user id (most apps stash it during login); fallback to email from body
        try:
            body = kwargs.get('body') or args[0]
            email = getattr(body, "email", None) if body else None
        except Exception:
            email = None
        # If response lacks refresh_token, add it
        if isinstance(res, dict) and "access_token" in res and "refresh_token" not in res:
            uid = res.get("user_id") or email or "user1@example.com"
            jti_new = str(uuid.uuid4())
            refresh = _make_jwt(uid, REFRESH_TTL, scope="refresh", jti=jti_new)
            try:
                r  # Redis client
                store_refresh_jti(r, uid, jti_new, {"issued_at": _now()})
            except Exception:
                pass
            res["refresh_token"] = refresh
            res.setdefault("token_type","bearer")
        return res
except Exception:
    pass

@app.post("/auth/refresh", response_model=TokenPair)
def auth_refresh(body: RefreshIn):
    data = _verify_jwt(body.refresh_token, scope="refresh")
    user_id = data.get("sub")
    jti_old = data.get("jti")
    if not user_id or not jti_old:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="invalid_refresh")
    try:
        r  # Redis client
    except NameError:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail="redis_not_configured")
    if not refresh_jti_exists(r, user_id, jti_old):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="refresh_reuse_or_revoked")
    delete_refresh_jti(r, user_id, jti_old)
    jti_new = str(uuid.uuid4())
    access  = _make_jwt(user_id, ACCESS_TTL, scope="access")
    refresh = _make_jwt(user_id, REFRESH_TTL, scope="refresh", jti=jti_new)
    store_refresh_jti(r, user_id, jti_new, {"issued_at": _now()})
    return TokenPair(access_token=access, refresh_token=refresh)

@app.post("/auth/logout")
def auth_logout(body: LogoutIn):
    data = _verify_jwt(body.refresh_token, scope="refresh")
    user_id = data.get("sub")
    jti     = data.get("jti")
    if not user_id or not jti:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="invalid_refresh")
    try:
        r  # Redis client
    except NameError:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail="redis_not_configured")
    delete_refresh_jti(r, user_id, jti)
    return {"status": "ok"}

# ---------- Logout all sessions ----------
@app.post("/auth/logout_all")
def logout_all(user: MeOut = Depends(get_current_user)):
    uid = user.email
    # remove all refresh tokens for this user
    for raw in r.smembers(f"refresh:index:{uid}") or []:
        jti = raw.decode() if isinstance(raw, (bytes, bytearray)) else raw
        r.delete(f"refresh:{uid}:{jti}")
    r.delete(f"refresh:index:{uid}")
    return {"status": "ok"}


def user_ping(user=Depends(get_current_user)):
    email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
    return {"ok": True, "user": email or "unknown"}

# ======== M8B UUID AUTH PATCH (append-only, complete) ========
# Rebind /auth/login to issue UUID-based tokens and resolve current user by user_uuid.

import os, psycopg
from fastapi import Body, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt, JWTError

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cgv:cgv@db:5432/cgv")

def _pg_ro():
    # autocommit True is fine for read queries
    return psycopg.connect(DATABASE_URL, autocommit=True)

# 1) prune any previously-registered /auth/login POST route
try:
    kept = []
    for r in app.router.routes:
        try:
            if getattr(r, "path", None) == "/auth/login" and "POST" in getattr(r, "methods", set()):
                continue
        except Exception:
            pass
        kept.append(r)
    app.router.routes = kept
except Exception as _e:
    print("[M8B] Warning pruning /auth/login:", _e)

# 2) new /auth/login: select user_uuid and issue tokens with sub=<uuid>
class _LoginInUUID(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/login", tags=["auth"])
def login_uuid(body: _LoginInUUID = Body(...)):
    import psycopg.rows
    with _pg_ro() as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("""
            SELECT id, email, role, password_hash, user_uuid
            FROM users
            WHERE lower(email)=lower(%s)
        """, (body.email,))
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # verify_password must already exist (imported earlier in this file)
    if not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    sub = str(row["user_uuid"])  # put UUID into sub
    access  = create_access_token(sub, row["role"])   # existing helper in your file
    refresh = _make_jwt(sub, REFRESH_TTL, scope="refresh")  # existing helper

    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

# 3) override get_current_user to resolve by user_uuid from JWT.sub
class _MeOutUUID(BaseModel):
    id: str   # uuid
    role: str

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> _MeOutUUID:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = creds.credentials
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], options={"verify_aud": False})
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    if data.get("iss") != JWT_ISSUER or not data.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    sub = data["sub"]  # UUID
    import psycopg.rows
    with _pg_ro() as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("""
            SELECT user_uuid, role
            FROM users
            WHERE user_uuid = %s
        """, (sub,))
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return _MeOutUUID(id=str(row["user_uuid"]), role=row["role"])

print("[M8B] UUID auth patch active: /auth/login re-bound; get_current_user uses user_uuid")
# ======== /M8B UUID AUTH PATCH ========

# ======== M8B: /auth/me (UUID) ========
# Returns the current user's UUID (id), email and role from the token's sub.

from fastapi import Depends
from pydantic import BaseModel
import psycopg, psycopg.rows

class MeOutUUID(BaseModel):
    id: str
    email: str | None = None
    role: str

@app.get("/auth/me", response_model=MeOutUUID, tags=["auth"])
def auth_me_uuid(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    # Verify + parse the JWT using the same settings already used elsewhere
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    sub = data.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject (sub)")

    # Look up the user by user_uuid (the token now carries UUID in sub)
    with psycopg.connect(os.getenv("DATABASE_URL", "postgresql://cgv:cgv@db:5432/cgv"),
                         autocommit=True) as conn, \
         conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute(
            "SELECT user_uuid::text AS id, email, role FROM users WHERE user_uuid = %s",
            (sub,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return row
# ======== M8C: Phone-first auth (append-only, complete) ========
from pydantic import BaseModel, Field
from fastapi import HTTPException
import os, re, random, psycopg, psycopg.rows

def _pg_rw():
    return psycopg.connect(os.getenv("DATABASE_URL", "postgresql://cgv:cgv@db:5432/cgv"),
                           autocommit=True)

def _norm_phone(s: str) -> str:
    s = (s or "").strip()
    if not s: return s
    if s.startswith('+'):
        return '+' + re.sub(r'[^0-9]', '', s[1:])
    return re.sub(r'[^0-9]', '', s)

class RegisterPhoneIn(BaseModel):
    phone: str = Field(..., min_length=5)
    password: str = Field(..., min_length=6)
    email: str | None = None
    role: str = "user"

class LoginPhoneIn(BaseModel):
    phone: str
    password: str

# --- ensure we have a Redis client named `r` ---
try:
    r  # type: ignore[name-defined]
except NameError:
    try:
        import redis  # type: ignore
        r = redis.Redis(
            host=os.getenv("REDIS_HOST","redis"),
            port=int(os.getenv("REDIS_PORT","6379")),
            decode_responses=False,
        )
        print("[M8C] Fallback Redis client created")
    except Exception as _e:
        print("[M8C] WARNING: No Redis client available:", _e)
        r = None  # OTP routes will fail fast if used without Redis

@app.post("/auth/register_phone", tags=["auth"])
def auth_register_phone(body: RegisterPhoneIn):
    phone = _norm_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=422, detail="Invalid phone")

    pw_hash = hash_password(body.password)  # existing helper

    with _pg_rw() as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("""
            INSERT INTO users (user_uuid, phone, email, password_hash, role, created_at, updated_at)
            VALUES (gen_random_uuid(), %s, %s, %s, %s, now(), now())
            RETURNING user_uuid, role
        """, (phone, body.email, pw_hash, body.role))
        row = cur.fetchone()

    sub = str(row["user_uuid"])
    access  = create_access_token(sub, row["role"])
    refresh = _make_jwt(sub, REFRESH_TTL, scope="refresh")
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

@app.post("/auth/login_phone", tags=["auth"])
def auth_login_phone(body: LoginPhoneIn):
    phone = _norm_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=422, detail="Invalid phone")

    with _pg_rw() as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("""
            SELECT user_uuid, role, password_hash
            FROM users
            WHERE LOWER(phone) = LOWER(%s)
        """, (phone,))
        row = cur.fetchone()

    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    sub = str(row["user_uuid"])
    access  = create_access_token(sub, row["role"])
    refresh = _make_jwt(sub, REFRESH_TTL, scope="refresh")
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

# ---- Passwordless OTP (dev only) ----
class OTPRequestIn(BaseModel):
    phone: str

class OTPVerifyIn(BaseModel):
    phone: str
    code: str

@app.post("/auth/otp/request", tags=["auth"])
def auth_otp_request(body: OTPRequestIn):
    if r is None:
        raise HTTPException(status_code=503, detail="OTP storage unavailable")
    phone = _norm_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=422, detail="Invalid phone")
    code = f"{random.randint(0, 999999):06d}"
    _otp_set(phone, code)
    print(f"[OTP] phone={phone} code={code}")
    return {"ok": True}

@app.post("/auth/otp/verify", tags=["auth"])
def auth_otp_verify(body: OTPVerifyIn):
    if r is None:
        raise HTTPException(status_code=503, detail="OTP storage unavailable")
    phone = _norm_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=422, detail="Invalid phone")
    saved = _otp_get(phone)
    if not saved or saved.decode() != body.code:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    _otp_del(phone)
    with _pg_rw() as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("SELECT user_uuid, role FROM users WHERE LOWER(phone)=LOWER(%s)", (phone,))
        row = cur.fetchone()
        if not row:
            cur.execute("""
                INSERT INTO users (user_uuid, phone, role, created_at, updated_at)
                VALUES (gen_random_uuid(), %s, 'user', now(), now())
                RETURNING user_uuid, role
            """, (phone,))
            row = cur.fetchone()
    sub = str(row["user_uuid"])
    access  = create_access_token(sub, row["role"])
    refresh = _make_jwt(sub, REFRESH_TTL, scope="refresh")
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}
# ======== /M8C ========
# ======== M8C HOTFIX: Redis rebind + /auth/me guard + OTP helpers ========
try:
    r  # noqa: F821
    from starlette.routing import BaseRoute
    if isinstance(r, BaseRoute) or not hasattr(r, "setex"):  # r was shadowed by a route
        raise NameError("shadowed r")
except Exception:
    try:
        import redis as _redis_mod
        r = _redis_mod.Redis(
            host=os.getenv("REDIS_HOST","redis"),
            port=int(os.getenv("REDIS_PORT","6379")),
            decode_responses=False,
        )
        print("[M8C] Redis client rebound as global r")
    except Exception as _e:
        print("[M8C] WARNING: Redis unavailable:", _e)
        r = None

# OTP helpers that always use the (re)bound client
def _otp_set(phone: str, code: str):
    if r is None or not hasattr(r, "setex"):
        raise HTTPException(status_code=503, detail="OTP storage unavailable")
    _otp_set(phone, code)

def _otp_get(phone: str) -> str | None:
    if r is None or not hasattr(r, "get"):
        raise HTTPException(status_code=503, detail="OTP storage unavailable")
    v = r.get(f"otp:{phone}")
    return None if v is None else v.decode()

def _otp_del(phone: str):
    if r is not None and hasattr(r, "delete"):
        _otp_del(phone)
# ======== /M8C HOTFIX ========
# ======== M8C FIX: robust get_current_user_proxy (UUID) ========
from fastapi.security import HTTPAuthorizationCredentials

def get_current_user_proxy(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    sub = data.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing subject")

    # Ensure user exists (and return id/role)
    import psycopg, psycopg.rows, os
    with psycopg.connect(os.getenv("DATABASE_URL", "postgresql://cgv:cgv@db:5432/cgv"),
                         autocommit=True) as conn, \
         conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("SELECT user_uuid::text AS id, role FROM users WHERE user_uuid=%s", (sub,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": row["id"], "role": row["role"]}
# ======== /M8C FIX ========
# ======== M8C FIX: prune & replace OTP routes using _otp_* helpers ========
# 1) prune old OTP routes (if any)
try:
    kept = []
    for route in app.router.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set())
        if path in ("/auth/otp/request", "/auth/otp/verify") and ("POST" in methods):
            continue
        kept.append(route)
    app.router.routes = kept
except Exception as _e:
    print("[M8C] Warning pruning OTP routes:", _e)

from pydantic import BaseModel

class _OtpRequestIn(BaseModel):
    phone: str

class _OtpVerifyIn(BaseModel):
    phone: str
    code: str

@app.post("/auth/otp/request", tags=["auth"])
def auth_otp_request(body: _OtpRequestIn):
    phone = _norm_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=422, detail="Invalid phone")
    # dev-only: random 6 digits; store for 5 minutes
    code = f"{random.randint(0, 999999):06d}"
    _otp_set(phone, code)
    print(f"[OTP] phone={phone} code={code}")
    return {"ok": True}

@app.post("/auth/otp/verify", tags=["auth"])
def auth_otp_verify(body: _OtpVerifyIn):
    phone = _norm_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=422, detail="Invalid phone")
    saved = _otp_get(phone)
    if saved is None or body.code != saved:
        raise HTTPException(status_code=401, detail="Invalid code")
    _otp_del(phone)

    # upsert user by phone, issue tokens
    import psycopg, psycopg.rows
    with _pg_rw() as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("SELECT user_uuid, role FROM users WHERE phone=%s", (phone,))
        row = cur.fetchone()
        if not row:
            cur.execute("""
                INSERT INTO users (user_uuid, phone, role, created_at, updated_at)
                VALUES (gen_random_uuid(), %s, 'user', now(), now())
                RETURNING user_uuid, role
            """, (phone,))
            row = cur.fetchone()

    sub = str(row["user_uuid"]); role = row["role"]
    access  = create_access_token(sub, role)
    refresh = _make_jwt(sub, REFRESH_TTL, scope="refresh")
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}
# ======== /M8C FIX ========
# ======== M8C HOTFIX: Redis rebind + OTP helpers (idempotent) ========
# Rebind a real Redis client to global `r` if it's shadowed / missing.
try:
    r  # may be a shadowed APIRoute
    from starlette.routing import BaseRoute
    if isinstance(r, BaseRoute) or not hasattr(r, "setex"):
        raise NameError("shadowed r")
except Exception:
    try:
        import os, redis as _redis_mod
        r = _redis_mod.Redis(
            host=os.getenv("REDIS_HOST","redis"),
            port=int(os.getenv("REDIS_PORT","6379")),
            decode_responses=False,
        )
        print("[M8C] Redis client (re)bound to `r`")
    except Exception as _e:
        print("[M8C] WARNING: Redis unavailable:", _e)
        r = None

# Small helpers so routes never touch `r` directly
def _otp_set(phone: str, code: str):
    from fastapi import HTTPException
    if r is None or not hasattr(r, "setex"):
        raise HTTPException(status_code=503, detail="OTP storage unavailable")
    r.setex(f"otp:{phone}", 300, code.encode())

def _otp_get(phone: str) -> str | None:
    from fastapi import HTTPException
    if r is None or not hasattr(r, "get"):
        raise HTTPException(status_code=503, detail="OTP storage unavailable")
    v = r.get(f"otp:{phone}")
    return None if v is None else v.decode()

def _otp_del(phone: str):
    if r is not None and hasattr(r, "delete"):
        r.delete(f"otp:{phone}")
# ======== /M8C HOTFIX ========
