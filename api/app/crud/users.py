from sqlalchemy.orm import Session
from typing import Optional, Iterable
from ..models.user import User, Role
from ..security import hash_password, verify_password

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, email: str, password: str, roles: Iterable[str] = (), is_superuser: bool=False) -> User:
    user = User(email=email, hashed_password=hash_password(password), is_superuser=is_superuser)
    # ensure roles exist or create
    role_objs = []
    for r in roles:
        obj = db.query(Role).filter(Role.name == r).first()
        if not obj:
            obj = Role(name=r)
            db.add(obj)
        role_objs.append(obj)
    user.roles = role_objs
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate(db: Session, email: str, password: str) -> Optional[User]:
    u = get_user_by_email(db, email)
    if not u or not verify_password(password, u.hashed_password):
        return None
    return u
