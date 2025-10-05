import os
import psycopg
# psycopg needs a plain 'postgresql://' DSN (no '+psycopg')
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+psycopg://cgv:cgv@db:5432/cgv')
DSN = DATABASE_URL.replace('postgresql+psycopg://', 'postgresql://', 1)

from db import engine
from sqlalchemy import text
from db import get_db, engine
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os
import time
import psycopg
import redis


# Prometheus metrics
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI()

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to your frontend origin in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- connection helpers ----------
RURL = os.getenv("REDIS_URL", "redis://redis:6379/0")
_r = redis.from_url(RURL)

# ---------- metrics ----------
REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "path", "status"]
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["method", "path"]
)

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.time()
    response = None
    try:
        response = await call_next(request)
        return response
    finally:
        duration = time.time() - start
        path = request.url.path
        method = request.method
        REQUEST_LATENCY.labels(method, path).observe(duration)
        status = str(response.status_code if response else 500)
        REQUEST_COUNT.labels(method, path, status).inc()

@app.get("/metrics")
def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

# ---------- very simple rate limit (per-IP) ----------
def ratelimit_ok(ip: str, key: str, limit: int = 120, window_sec: int = 60) -> bool:
    """
    Allow up to `limit` hits per `window_sec` per ip:key. Uses Redis INCR + EXPIRE.
    Fail-open (returns True) if Redis is unavailable.
    """
    rk = f"rl:{key}:{ip}"
    try:
        hits = _r.incr(rk)
        if hits == 1:
            _r.expire(rk, window_sec)
        return hits <= limit
    except Exception:
        return True  # don't block if Redis is down

@app.middleware("http")
async def basic_rate_limit(request: Request, call_next):
    path = request.url.path
    # skip health/metrics/probes
    if not path.startswith(("/healthz", "/ready", "/metrics", "/dbz", "/cachez")):
        ip = (request.client.host if request.client else "unknown")
        if not ratelimit_ok(ip, key="global", limit=120, window_sec=60):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
    return await call_next(request)

# ---------- startup: ensure schema ----------

def ensure_schema():
    ddl = """
    CREATE TABLE IF NOT EXISTS notes(
      id SERIAL PRIMARY KEY,
      msg TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    """
    try:
        with psycopg.connect(DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
    except Exception as e:
        print("[startup] schema ensure failed:", e)

# ---------- base health ----------
@app.get("/healthz")
def health():
    return {"status": "ok"}

# ---------- ready: DB + Redis ----------
@app.get("/ready")
def ready():
    out = {"db": False, "cache": False}
    try:
        with psycopg.connect(DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                _ = cur.fetchone()[0]
        out["db"] = True
    except Exception as e:
        out["db_error"] = str(e)
    try:
        out["cache"] = bool(_r.ping())
    except Exception as e:
        out["cache_error"] = str(e)
    out["ok"] = out["db"] and out["cache"]
    return out

# ---------- quick probes ----------
@app.get("/dbz")
def db_probe():
    try:
        with psycopg.connect(DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                v = cur.fetchone()[0]
        return {"ok": True, "select1": v}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/cachez")
def cache_probe():
    try:
        pong = _r.ping()
        return {"ok": True, "ping": pong}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------- version ----------
@app.get("/version")
def version():
    return {
        "version": os.getenv("APP_VERSION", "dev"),
        "commit": os.getenv("GIT_COMMIT", "unknown"),
    }

# ---------- notes endpoints ----------
class NoteIn(BaseModel):
    msg: str

class NoteOut(BaseModel):
    id: int
    msg: str
    created_at: str

@app.post("/notes", response_model=NoteOut)
def create_note(n: NoteIn):
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO notes(msg) VALUES (%s) RETURNING id, msg, created_at",
                (n.msg,)
            )
            row = cur.fetchone()
            return {"id": row[0], "msg": row[1], "created_at": row[2].isoformat()}

@app.get("/notes", response_model=List[NoteOut])
def list_notes(limit: int = 10):
    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, msg, created_at FROM notes ORDER BY id DESC LIMIT %s",
                (limit,)
            )
            rows = cur.fetchall()
            return [{"id": r[0], "msg": r[1], "created_at": r[2].isoformat()} for r in rows]

# ---------- simple cache endpoints ----------
class CacheIn(BaseModel):
    key: str
    value: str
    ttl_seconds: Optional[int] = None

@app.post("/cache")
def cache_set(c: CacheIn):
    if c.ttl_seconds:
        _r.setex(c.key, c.ttl_seconds, c.value)
    else:
        _r.set(c.key, c.value)
    return {"ok": True, "key": c.key}

@app.get("/cache/{key}")
def cache_get(key: str):
    val = _r.get(key)
    if val is None:
        return {"ok": False, "key": key, "value": None}
    return {"ok": True, "key": key, "value": val.decode("utf-8")}

@app.on_event("startup")
def ensure_schema():
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS notes (
                    id SERIAL PRIMARY KEY,
                    msg TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))
    except Exception as e:
        print(f"[startup] schema ensure failed: {e}")
