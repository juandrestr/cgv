from fastapi import FastAPI, Depends
import rbac_m7
from fastapi.routing import APIRoute
import psycopg
import json

from routers import reports
import os, time, uuid
from jose import jwt, JWTError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
import os
import redis

from db import get_conn
from auth import hash_password, verify_password, create_access_token, decode_token

from routers import reports
app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"ok": True}


# --- M12: safe include of optional routers ---
import importlib, logging
log = logging.getLogger("cgv.main")

def safe_include(module_name: str, attr: str = "router"):
    try:
        mod = importlib.import_module(f"routers.{module_name}")
    except Exception as e:
        log.warning("Skipping router %s: import failed: %s", module_name, e)
        return
    r = getattr(mod, attr, None)
    if r is None:
        log.warning("Skipping router %s: attribute '%s' missing", module_name, attr)
        return
    try:
        app.include_router(r)
    except Exception as e:
        log.warning("Skipping router %s: include failed: %s", module_name, e)
# --- end safe include ---


app.include_router(reports.router)
from routers.vouchers import router as vouchers_router




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
        cur.execute("SELECT is_admin FROM users WHERE email=%s LIMIT 1;", (email,))
        row = cur.fetchone()
        return bool(row and row[0])
def require_admin(user=None):
    return
