from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path
import os

ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(ENV_PATH)

class Settings(BaseSettings):
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))
    ENVIRONMENT: str = os.getenv("ENVIRONMENT")

settings = Settings()