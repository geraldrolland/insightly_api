from pwdlib import PasswordHash
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os


load_dotenv(".env")




password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hasher.verify(plain_password, hashed_password)

def generate_access_token(data: dict):
    from insightly_api.main import redis_client
    import uuid

    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    to_encode.update({"exp": expire})
    access_token = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    refresh_token = str(uuid.UUID())
    redis_client.set(name=refresh_token, ex=os.getenv("REFRESH_TOKEN_EXP"), value=str(data))
    redis_client.set(name=access_token, value=refresh_token)
    return access_token

def verify_access_token(token: str):
    payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
    return payload

def refresh_access_token(access_token: str):
    from jwt.exceptions import ExpiredSignatureError
    from insightly_api.main import redis_client
    from .exceptions import ExpiredRefreshTokenError

    try:
        verify_access_token(access_token)
    except ExpiredSignatureError:
        refresh_token = redis_client.get(access_token)
        payload = redis_client.get(refresh_token)
        if not payload:
            raise ExpiredRefreshTokenError()
        expire = datetime.now(timezone.utc) + timedelta(minutes=os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
        payload["exp"] = expire
        new_access_token = jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
        redis_client.rename(access_token, new_access_token)
        return new_access_token




