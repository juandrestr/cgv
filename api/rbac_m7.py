import os
import psycopg
import importlib
from typing import Optional

import jwt  # PyJWT
from fastapi import Depends, HTTPException, Request
from fastapi.routing import APIRoute

def _db():
    url = os.getenv("DATABASE_URL") or "postgresql://cgv:cgv@db:5432/cgv"
    return psycopg.connect(url)

def _is_admin(email: str) -> bool:
    if not email:
        return False
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT is_admin FROM users WHERE email=%s LIMIT 1;", (email,))
        row = cur.fetchone()
        return bool(row and row[0])

def _jwt_secret() -> Optional[str]:
    for k in ("JWT_SECRET", "SECRET_KEY", "ACCESS_TOKEN_SECRET"):
        v = os.getenv(k)
        if v:
            return v
    return None

def _get_user_from_bearer(request: Request):
    """Read Authorization: Bearer <token>, verify HS256 if secret present, return {'email': sub}."""
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split(" ", 1)[1].strip()
    secret = _jwt_secret()
    try:
        if secret:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        else:
            payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"email": sub}

def setup(app):
    """
    - Promote ADMIN_EMAILS to is_admin=TRUE on startup
    - Enforce admin-only on /auth/register when ENFORCE_ADMIN_ON_REGISTER != '0'
    - Add /user/ping requiring any authenticated user
    """
    # Prefer main.get_current_user; fallback to JWT header reader
    try:
        main = importlib.import_module("main")
        get_current_user = getattr(main, "get_current_user", None)
    except Exception:
        get_current_user = None
    if get_current_user is None:
        get_current_user = _get_user_from_bearer

    def require_admin(user=Depends(get_current_user)):
        email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
        if not email or not _is_admin(email):
            raise HTTPException(status_code=403, detail="Admin privileges required.")
        return user

    @app.on_event("startup")
    def _startup_promote_and_protect():
        # 1) promote configured admins
        raw = os.getenv("ADMIN_EMAILS", "").strip()
        if raw:
            emails = [e.strip().lower() for e in raw.split(",") if e.strip()]
            if emails:
                with _db() as conn, conn.cursor() as cur:
                    cur.execute("UPDATE users SET is_admin=TRUE WHERE lower(email) = ANY(%s);", (emails,))
                    conn.commit()

        # 2) guard /auth/register dynamically (if enabled)
        enforce = os.getenv("ENFORCE_ADMIN_ON_REGISTER", "1") != "0"
        if enforce:
            try:
                for r in app.router.routes:
                    if isinstance(r, APIRoute) and r.path == "/auth/register" and "POST" in r.methods:
                        dep_names = [
                            getattr(getattr(d, "dependency", None), "__name__", "")
                            for d in getattr(r, "dependencies", [])
                        ]
                        if "require_admin" not in dep_names:
                            current = list(getattr(r, "dependencies", []))
                            current.append(Depends(require_admin))
                            r.dependencies = current
            except Exception as e:
                print(f"[M7] Warning: could not attach admin guard to /auth/register: {e}")

    @app.get("/user/ping")
    def user_ping(user=Depends(get_current_user)):
        email = getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)
        return {"ok": True, "user": email or "unknown"}
