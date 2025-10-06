from app.db import SessionLocal
from app.crud.users import create_user, get_user_by_email
import os, sys
email = os.getenv("SEED_ADMIN_EMAIL") or (sys.argv[1] if len(sys.argv) > 1 else None)
password = os.getenv("SEED_ADMIN_PASSWORD") or (sys.argv[2] if len(sys.argv) > 2 else None)
if not email or not password:
    print("Usage: python -m app.cli.seed_admin <email> <password>")
    sys.exit(1)
db = SessionLocal()
try:
    if get_user_by_email(db, email):
        print("Admin already exists.")
    else:
        create_user(db, email, password, roles=("admin",), is_superuser=True)
        print("Admin created:", email)
finally:
    db.close()
