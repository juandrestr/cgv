import os
import time
from typing import Tuple
from passlib.context import CryptContext
from jose import jwt

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG    = "HS256"
JWT_TTL_S  = int(os.getenv("JWT_TTL_SECONDS", "3600"))

def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_access_token(sub: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": sub, "role": role, "iat": now, "exp": now + JWT_TTL_S, "iss": "cgv-api"}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> Tuple[str, str]:
    data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    return data["sub"], data.get("role", "user")
