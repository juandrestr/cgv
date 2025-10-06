from pydantic import BaseModel
import os

class Settings(BaseModel):
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me")
    JWT_ALGO: str = os.getenv("JWT_ALGO", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

settings = Settings()
