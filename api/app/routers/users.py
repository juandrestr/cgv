from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..routers.auth import get_current_user
from ..schemas.user import UserOut, UserCreate
from ..crud.users import create_user
from ..models.user import User
from ..deps.deps import get_db

router = APIRouter(prefix="/users", tags=["users"])

def require_admin(user: User):
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")

@router.get("/me", response_model=UserOut)
def me(current: User = Depends(get_current_user)):
    return current

@router.post("", response_model=UserOut, status_code=201)
def create_user_admin(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    require_admin(current)
    user = create_user(db, payload.email, payload.password, roles=(), is_superuser=False)
    return user
