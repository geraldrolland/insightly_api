from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
from pathlib import Path
import os

ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(ENV_PATH)

class Settings(BaseSettings):
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int
    ENVIRONMENT: str 
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_FROM_NAME: str
    MAIL_USERNAME: str
    APP_HOST: str
    API_HOST: str
    SECRET_KEY: str
    COOKIE_SALT: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int
    COOKIE_SECURE: bool
    COOKIE_SAMESITE: str
    ENVIRONMENT: str
    CLIENT_ID: str
    CLIENT_SECRET: str
    GOOGLE_ACCESS_TOKEN_OBTAIN_URL: str
    GOOGLE_USER_INFO_URL: str

    model_config = SettingsConfigDict(env_file=ENV_PATH)

settings = Settings()