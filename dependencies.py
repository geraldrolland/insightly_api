from insightly_api.utils import verify_signed_cookie
from .type import UserRegistrationType, Annotated
from fastapi.exceptions import HTTPException
from .db_config import engine
from sqlmodel import  Session, select
from fastapi import Request, Response, Depends

async def check_agreetoTermsandPolicy(data: UserRegistrationType):
    if data.agree_toTermsAndPolicy != True:
        raise HTTPException(status_code=400, detail="user must agree to terms and policy before proceeding with registration")
    return data

async def get_session():
    with Session(engine) as session:
        yield session


async def authenticate_user(request: Request, response: Response, session: Annotated[Session, Depends(get_session)]):
    from insightly_api.utils import verify_access_token, refresh_access_token, verify_signed_cookie, sign_cookie
    from fastapi.exceptions import HTTPException
    from jwt.exceptions import ExpiredSignatureError
    from .models.user_model import User
    from insightly_api.exceptions import ExpiredRefreshTokenError
    from dotenv import load_dotenv
    import os

    load_dotenv(".env")

    signed_access_token = request.cookies.get("access_token")
    if not signed_access_token:
        raise HTTPException(status_code=401, detail="access token missing in cookies")
    access_token = None
    try:
        access_token = verify_signed_cookie(signed_access_token)
        payload = verify_access_token(access_token)
        user = session.exec(select(User).where(User.email == payload.get("email"))).first()
        if not user:
            raise HTTPException(status_code=401, detail="user not found")
        request.state.auth_user = user
    except ExpiredSignatureError:
        try:
            new_access_token = refresh_access_token(access_token)
            payload = verify_access_token(new_access_token)
            user = session.exec(select(User).where(User.email == payload.get("email"))).first()
            if not user:
                raise HTTPException(status_code=401, detail="user not found")
            request.state.auth_user = user 
            signed_new_access_token = sign_cookie(new_access_token)
            response.set_cookie(key="access_token", 
                                value=signed_new_access_token, 
                                httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), 
                                samesite=os.getenv("COOKIE_SAMESITE"))
        except ExpiredRefreshTokenError:
            raise HTTPException(status_code=401, detail="refresh token expired. please login again")
    except Exception as e:
        raise HTTPException(status_code=401, detail="invalid access token cookie")
    