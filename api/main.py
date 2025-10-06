from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
import os
import redis

from db import get_conn
from auth import hash_password, verify_password, create_access_token, decode_token

app = FastAPI()

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
        row = conn.execute("SELECT email, role, is_active FROM users WHERE email=%s", (email,)).fetchone()
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
        row = conn.execute("SELECT id FROM users WHERE email=%s", (admin_email,)).fetchone()
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
            "SELECT email, password_hash, role, is_active FROM users WHERE email=%s",
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
    token = create_access_token(row["email"], row["role"])
    return {"access_token": token, "token_type": "bearer"}

# ---------- Register (admin only) ----------
@app.post("/auth/register")
def register(body: RegisterIn, admin: MeOut = Depends(require_admin)):
    if body.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")
    with get_conn() as conn, conn.cursor() as cur:
        exists = conn.execute("SELECT 1 FROM users WHERE email=%s", (body.email,)).fetchone()
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
