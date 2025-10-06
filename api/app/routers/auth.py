from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from ..deps.deps import get_db
from ..crud.users import authenticate
from ..security import create_access_token
from ..schemas.user import TokenOut
from ..models.user import User
from jose import jwt, JWTError
from ..core.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(subject=str(user.id))
    return {"access_token": token}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGO])
        sub = payload.get("sub")
        if sub is None:
            raise credentials_exception
        user = db.get(User, int(sub))
        if not user or not user.is_active:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

@router.get("/me")
def auth_me(current=Depends(get_current_user)):
    # mirrors /users/me but lives under /auth
    from ..schemas.user import UserOut
    return UserOut.model_validate(current)
