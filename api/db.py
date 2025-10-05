import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DEFAULT_URL = "postgresql+psycopg://postgres:postgres@db:5432/postgres"
url = os.getenv("DATABASE_URL", DEFAULT_URL)
if url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    url,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

@contextmanager
def session_scope():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
