from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Uses DATABASE_URL from your existing config/.env via Docker compose
import os
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@db:5432/postgres")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
Base = declarative_base()
