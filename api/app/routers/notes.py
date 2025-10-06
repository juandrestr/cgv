from fastapi import APIRouter
from sqlalchemy import text
from app.db import engine

router = APIRouter()

@router.get("/")
def list_notes():
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id, msg, created_at FROM notes ORDER BY id DESC"
        )).mappings().all()
        return [dict(r) for r in rows]

@router.post("/")
def create_note(note: dict):
    msg = note.get("msg")
    with engine.begin() as conn:
        row = conn.execute(
            text("INSERT INTO notes(msg) VALUES (:m) RETURNING id, msg, created_at"),
            {"m": msg},
        ).mappings().first()
        return dict(row)
