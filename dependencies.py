from .type import UserRegistrationType
from fastapi.exceptions import HTTPException
from .db_config import engine
from sqlmodel import  Session
from fastapi import Request, Response

async def check_agreetoTermsandPolicy(data: UserRegistrationType):
    if data.agree_toTermsAndPolicy != True:
        raise HTTPException(status_code=400, detail="user must agree to terms and policy before proceeding with registration")
    return data

async def get_session():
    with Session(engine) as session:
        yield session


async def authenticate_user(request: Request, response: Response):
    from insightly_api.utils import verify_access_token
    pass
        