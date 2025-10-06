from fastapi import HTTPException, status
from .models.user import User

def require_roles(user: User, *roles: str):
    have = {r.name for r in user.roles}
    need = set(roles)
    if not need.issubset(have):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires roles: {', '.join(sorted(need))}")
