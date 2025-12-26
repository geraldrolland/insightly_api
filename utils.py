from pwdlib import PasswordHash
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
from random import choice
from email.mime.multipart import MIMEMultipart
from jinja2 import FileSystemLoader, Environment
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer

load_dotenv(".env")



SECRET_KEY = os.getenv("SECRET_KEY")
COOKIE_SALT = os.getenv("COOKIE_SALT")

serializer = URLSafeTimedSerializer(
    secret_key=SECRET_KEY,
    salt=COOKIE_SALT
)


password_hasher = PasswordHash.recommended()


def hash(password: str) -> str:
    return password_hasher.hash(password)

def verify_hash(plain_password: str, hashed_password: str) -> bool:
    return password_hasher.verify(plain_password, hashed_password)

def generate_access_token(data: dict):
    from insightly_api.core.settings import settings
    from insightly_api.main import redis_client
    import uuid
    import json

    to_encode = data.copy()
    session_id = str(uuid.uuid4())
    access_token_expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": access_token_expire})
    access_token = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    refresh_token = jwt.encode({"exp": refresh_token_expire, "session_id": session_id}, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    to_encode.pop("exp", None)
    to_encode.update({"hashed_refresh_token": hash(refresh_token)})
    redis_client.set(name=session_id, value=json.dumps(to_encode), ex=3600*24*3)
    return access_token, refresh_token

def verify_access_token(token: str):
    payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
    return payload

def refresh_access_token(refresh_token: str):
    from insightly_api.main import redis_client
    from .exceptions import ExpiredRefreshTokenError
    import uuid
    import json
    from insightly_api.core.settings import settings

    try:
        payload = jwt.decode(refresh_token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
    except jwt.ExpiredSignatureError:
        raise ExpiredRefreshTokenError("refresh token has expired, please log in again")
    session_id = payload.get("session_id")
    stored_data = json.loads(redis_client.get(session_id))
    if not verify_hash(refresh_token, stored_data.get("hashed_refresh_token")):
        raise ExpiredRefreshTokenError("refresh token is invalid, please log in again")
    payload = stored_data.copy()
    payload.pop("hashed_refresh_token", None)
    new_access_token = jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    new_session_id = str(uuid.uuid4())
    new_refresh_token_expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    new_refresh_token = jwt.encode({"exp": new_refresh_token_expire, "session_id": new_session_id}, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    redis_client.set(name=new_session_id, value=json.dumps(stored_data.update({"hashed_refresh_token": hash(new_refresh_token)})), ex=3600*24*3)
    redis_client.delete(session_id)
    return new_access_token, new_refresh_token

def generate_verification_link(email: str, next: str):
    from insightly_api.main import redis_client
    import uuid

    token = str(uuid.uuid4())
    redis_client.set(name=token, value=email, ex=7*60)
    verification_link = f"{os.getenv('APP_HOST')}/verify_email?token={token}&next={next}"
    return verification_link

def generate_otp(length: int):
    digit = ["0", "1", "2", "3",
             "4", "5","6", "7","8", "9"
             ]
    otp = ""
    for i in range(length):
        i = choice(digit)
        otp += i
    return otp


def send_mail(email: str, subject: str, template: str, body: dict[str, str]=None):

    BASE_DIR = Path(__file__).resolve().parent
    TEMPLATE_DIR = BASE_DIR / "templates"

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(template)
    html_content =  template.render(body)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject 
    msg["From"] = os.getenv("MAIL_FROM")
    msg["To"] = email
    
    msg.attach(MIMEText(html_content, "html"))
    with smtplib.SMTP(os.getenv("MAIL_SERVER"), int(os.getenv("MAIL_PORT"))) as server:
        server.starttls()
        server.login(
            os.getenv("MAIL_USERNAME"),
            os.getenv("MAIL_PASSWORD")
        )
        server.send_message(msg)

def log_to_file(message: str):
    filename = "error.log"
    try:
        with open(filename, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} - {message}\n")
    except FileNotFoundError:
        with open(filename, "w") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} - {message}\n")


def sign_cookie(value: dict[str, any] | str) -> str:
    return serializer.dumps(value)

def verify_signed_cookie(signed_value: str, max_age: int = None) -> dict[str, any] | str:
    return serializer.loads(signed_value, max_age=max_age)



