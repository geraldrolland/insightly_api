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
from ua_parser import user_agent_parser
from fastapi import UploadFile
import pandas as pd
from typing import List, Dict, Any
from collections import defaultdict



serializer = URLSafeTimedSerializer(
    secret_key=settings.SECRET_KEY,
    salt=settings.COOKIE_SALT
)


password_hasher = PasswordHash.recommended()


def normalize_user_agent(user_agent: str) -> str:
    parser = user_agent_parser.Parse(user_agent)
    browser = parser['user_agent']['family']
    os = parser['os']['family']

    return f"{browser}-{os}"

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
    data["user-agent"] = hash(normalize_user_agent(data.get("user-agent")))
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

def extract_data_via_api(api_url: str, is_auth_required: bool, headers: dict[str, str] | None = None):
    import requests

    MAX_ROWS = 10_000
    MAX_FILE_SIZE = 5 * 1024 * 1024   # 5MB

    response = None
    if is_auth_required:
        response = requests.get(api_url, headers=headers)
    else:
        response = requests.get(api_url)
    response.raise_for_status()
    data = response.json()

    if type(data) is dict:
        flag = 0
        for _, value in data.items():
            if type(value) is list and type(value[0]) is dict:
                data = value
                flag = 1
        if flag == 0:
            raise ValueError("malformed api response cannot extract data")
    
    elif type(data) is list and type(data[0]) is not dict:
        raise ValueError("malformed api response cannot extract data")
      
    if len(data) > MAX_ROWS:
        raise ValueError("number of rows exceeds the maximum allowed limit")
    if len(response.content) > MAX_FILE_SIZE:
        raise ValueError("file size exceeds the maximum allowed limit")
    
    file_name = ingest_data_to_csv(data)

def ingest_data_to_csv(data: list[dict]):
    import uuid
    import os

    file_name = f"{str(uuid.uuid4())}.csv"
    BASE_DIR = Path(__file__).resolve().parent
    RAW_FILE_DIR = BASE_DIR / "raw_data"
    os.makedirs(RAW_FILE_DIR, exist_ok=True)
    
    with open(RAW_FILE_DIR / file_name, mode="w") as file:
        headers = data[0].keys().join(",")
        file.write(headers)
        for item in data:
            record = item.values().join(",")
            file.write(record)
    
    return file_name

def extract_data_via_file(file: UploadFile):
    pass

def extract_data_from_excel(file: UploadFile):

    MAX_FILE_SIZE = 5 * 1024 * 1024   # 5MB
    MAX_ROWS = 10_000
   # 1️⃣ Validate extension
    if not file.filename.lower().endswith(".xlsx"):
        raise ValueError("unsupported file type. only .xlsx files are allowed")

    # 2️⃣ Validate content type (extra safety)
    if file.content_type not in (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/octet-stream",
    ):
        raise ValueError("unsupported content type for .xlsx file")

    # 3️⃣ Validate file size
    contents = file.file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise ValueError("file size exceeds the maximum allowed limit")

    # Reset file pointer for pandas
    file.file.seek(0)

    # 4️⃣ Load Excel file
    try:
        excel_file = pd.ExcelFile(file.file)
    except Exception:
        raise ValueError("failed to load Excel file")

    # 5️⃣ Process each sheet
    if len(excel_file.sheet_names) != 1:
        raise ValueError("only one sheet is allowed in the Excel file")
    sheet_name  = excel_file.sheet_names[0]
    df = excel_file.parse(sheet_name)

    # 6️⃣ Limit rows (security + performance)
    if len(df) > MAX_ROWS:
        raise ValueError("number of rows exceeds the maximum allowed limit")

    # 7️⃣ Normalize data
    df = df.fillna("")  # Replace NaN
    df.columns = df.columns.astype(str)

    data = df.to_dict(orient="records")

    file_name = ingest_data_to_csv(data)


def extract_data_from_json(file: UploadFile):
    import json
    
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_ROWS = 10_000
    
    content = file.file.read()
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("invalid JSON file")
    if type(data) is dict:
        flag = 0
        for _, value in data.items():
            if type(value) is list and type(value[0]) is dict:
                data = value
                flag = 1
        if flag == 0:
            raise ValueError("malformed JSON file cannot extract data")
    elif type(data) is list and type(data[0]) is not dict:
        raise ValueError("malformed JSON file cannot extract data")
    
    if len(data) > MAX_ROWS:
        raise ValueError("number of rows exceeds the maximum allowed limit")
    if len(content) > MAX_FILE_SIZE:
        raise ValueError("file size exceeds the maximum allowed limit")
    
    file_name = ingest_data_to_csv(data)

def extract_data_from_csv(file: UploadFile):
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_ROWS = 10_000

    # 1️⃣ Validate extension
    if not file.filename.lower().endswith(".csv"):
        raise ValueError("unsupported file type. only .csv files are allowed")
    # 2️⃣ Validate content type (extra safety)
    if file.content_type not in ("text/csv", "application/vnd.ms-excel", "application/octet-stream"):
        raise ValueError("unsupported content type for .csv file")
    # 3️⃣ Validate file size
    contents = file.file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise ValueError("file size exceeds the maximum allowed limit") 
    # Reset file pointer for pandas
    file.file.seek(0)
    # 4️⃣ Load CSV file
    try:
        df = pd.read_csv(file.file)
    except Exception:
        raise ValueError("failed to load CSV file")
    # 5️⃣ Limit rows (security + performance)
    if len(df) > MAX_ROWS:
        raise ValueError("number of rows exceeds the maximum allowed limit")
    # 6️⃣ Normalize data
    df = df.fillna("")  # Replace NaN
    df.columns = df.columns.astype(str)
    data = df.to_dict(orient="records")
    
    file_name = ingest_data_to_csv(data)


def extract_data_via_database_connection(db_type: str, username: str, password: str, database_name: str, host: str, query: str):
    from sqlalchemy import create_engine
    
    MAX_ROWS = 10_000
    MAX_FILE_SIZE = 5 * 1024 * 1024   # 5MB

    db_url = generate_db_url(db_type, username, password, database_name, host)
    engine = create_engine(db_url)
    with engine.connect() as connection:
        data = connection.execute(query).fetchall()
        if data == []:
            raise ValueError("query returned no data")
        else:
            columns = data[0].keys()
            data_dicts = [dict(zip(columns, row)) for row in data]
            if len(data_dicts) > MAX_ROWS:
                raise ValueError("number of rows exceeds the maximum allowed limit")
            if len(str(data_dicts)) > MAX_FILE_SIZE:
                raise ValueError("file size exceeds the maximum allowed limit")
            file_name = ingest_data_to_csv(data_dicts)
            
            return file_name

def generate_db_url(db_type: str, username: str, password: str, database_name: str, host: str) -> str:
    if db_type == "postgresql":
        return f"postgresql+psycopg2://{username}:{password}@{host}/{database_name}"
    elif db_type == "mysql":
        return f"mysql+pymysql://{username}:{password}@{host}/{database_name}"
    elif db_type == "sqlite":
        return f"sqlite:///{database_name}"
    else:
        raise ValueError("unsupported database type")

def infer_schema(data: List[Dict[str, Any]]):
    schema = defaultdict(dict)
    for col in data[0].keys():
        values = [row.get(col) for row in data]
        # Determine type
        if all(isinstance(v, int) or (isinstance(v, str) and v.isdigit()) for v in values if v not in [None, ""]):
            col_type = "int"
        elif all(isinstance(v, float) or (isinstance(v, str) and v.replace(".", "", 1).isdigit()) for v in values if v not in [None, ""]):
            col_type = "float"
        else:
            col_type = "str"
        # Determine if nullable
        nullable = any(v in [None, ""] for v in values)
        schema[col] = {"type": col_type, "nullable": nullable}
    return dict(schema)
"""
data = [
    {"name": "Alice", "age": "25", "email": "alice@test.com"},
    {"name": "Bob", "age": "30", "email": "bob@test.com"}
]

{
  "name": {"type": "str", "nullable": False},
  "age": {"type": "int", "nullable": False},
  "email": {"type": "str", "nullable": False}
}
"""