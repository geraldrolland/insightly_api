from pwdlib import PasswordHash
import jwt
from datetime import datetime, timedelta, timezone
from random import choice
from email.mime.multipart import MIMEMultipart
from jinja2 import FileSystemLoader, Environment
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer
from insightly_api.core.settings import settings



serializer = URLSafeTimedSerializer(
    secret_key=settings.SECRET_KEY,
    salt=settings.COOKIE_SALT
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


    session_id = str(uuid.uuid4())
    access_token_expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    access_token_payload = {
        "exp": access_token_expire,
        "sid": session_id,
        "type": "access_token"
    }

    refresh_token_payload = {
        "exp": refresh_token_expire,
        "sid": session_id,
        "type": "refresh_token"
    }
    access_token = jwt.encode(access_token_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    refresh_token = jwt.encode(refresh_token_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    redis_client.set(name=f'session:{session_id}', value=json.dumps(data), ex=3600*24*settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return access_token, refresh_token

def verify_access_token(token: str):
    from insightly_api.core.settings import settings
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    if payload.get("type") != "access_token":
        raise ValueError("invalid access token")
    return payload

def refresh_access_token(refresh_token: str):
    from insightly_api.main import redis_client
    from .exceptions import ExpiredRefreshTokenError
    import uuid
    import json
    from insightly_api.core.settings import settings

    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise ExpiredRefreshTokenError("refresh token has expired, please log in again")
    if payload.get("type") != "refresh_token":
        raise ExpiredRefreshTokenError("invalid refresh token, please log in again")
    session_id = payload.get("sid")
    stored_data = redis_client.get(session_id)
    if not stored_data:
        raise ExpiredRefreshTokenError("refresh token session has expired, please log in again")
    stored_data = json.loads(stored_data)
    new_session_id = str(uuid.uuid4())
    access_token_expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    refresh_token_payload = {
        "exp": refresh_token_expire,
        "sid": new_session_id,
        "type": "refresh_token"
    }
    access_token_payload = {
        "exp": access_token_expire,
        "sid": new_session_id,
        "type": "access_token"
    }
    new_access_token = jwt.encode(access_token_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    new_refresh_token = jwt.encode(refresh_token_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    redis_client.delete(name=f'session:{session_id}')
    redis_client.set(name=f'session:{new_session_id}', value=json.dumps(stored_data), ex=3600*24*settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return new_access_token, new_refresh_token

def generate_verification_link(email: str, next: str):
    from insightly_api.main import redis_client
    import uuid

    token = str(uuid.uuid4())
    redis_client.set(name=token, value=email, ex=7*60)
    verification_link = f"{settings.APP_HOST}/verify_email?token={token}&next={next}"
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
    msg["From"] = settings.MAIL_FROM
    msg["To"] = email
    
    msg.attach(MIMEText(html_content, "html"))
    with smtplib.SMTP(settings.MAIL_SERVER, settings.MAIL_PORT) as server:
        server.starttls()
        server.login(
            settings.MAIL_USERNAME,
            settings.MAIL_PASSWORD
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



