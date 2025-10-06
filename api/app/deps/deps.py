from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from ..db import SessionLocal
from ..core.config import settings
from ..models.user import User
from pydantic import BaseModel

class TokenPayload(BaseModel):
    sub: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(lambda: None), db: Session = Depends(get_db)):
    """
    Expecting 'Authorization: Bearer <token>' handled via OAuth2PasswordBearer in router.
    We'll wire the oauth2 scheme inside routers.auth and pass the token through context.
    """
    raise NotImplementedError("Router provides get_current_user implementation")
