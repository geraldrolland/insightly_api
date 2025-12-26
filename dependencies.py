from insightly_api.utils import verify_signed_cookie
from .type import UserRegistrationType, Annotated
from fastapi.exceptions import HTTPException
from .db_config import get_engine
from sqlmodel import  Session, select
from fastapi import Request, Response, Depends
from insightly_api.utils import verify_access_token, refresh_access_token, verify_signed_cookie, sign_cookie

async def check_agreetoTermsandPolicy(data: UserRegistrationType):
    if data.agree_toTermsAndPolicy != True:
        raise HTTPException(status_code=400, detail="user must agree to terms and policy before proceeding with registration")
    return data


async def get_session():
    with Session(get_engine()) as session:
        yield session


def get_test_session():
    return Session(get_engine())




async def authenticate_user(request: Request, response: Response, session: Annotated[Session, Depends(get_session)]):
    from fastapi.exceptions import HTTPException
    from jwt.exceptions import ExpiredSignatureError
    from .models.user_model import User
    from insightly_api.exceptions import ExpiredRefreshTokenError
    from dotenv import load_dotenv
    import os

    load_dotenv(".env")

    try:
        payload = verify_signed_cookie(request.cookies.get("auth_token"))
    except Exception:
        raise HTTPException(status_code=401, detail="invalid or missing auth token cookie")
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    try:
        payload = verify_access_token(access_token)
        user = session.exec(select(User).where(User.email == payload.get("email"))).first()
        if not user:
            raise HTTPException(status_code=401, detail="user not found")
        request.state.auth_user = user
        response.set_cookie(key="auth_token", 
                            value=request.cookies.get("auth_token"), 
                            httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), 
                            samesite=os.getenv("COOKIE_SAMESITE"))
    except ExpiredSignatureError:
        try:
            new_access_token, new_refresh_token = refresh_access_token(refresh_token)
            payload = verify_access_token(new_access_token)
            user = session.exec(select(User).where(User.email == payload.get("email"))).first()
            if not user:
                raise HTTPException(status_code=401, detail="user not found")
            request.state.auth_user = user 
            value = sign_cookie({"access_token": new_access_token, "refresh_token": new_refresh_token})
            response.set_cookie(key="auth_token", 
                                value=value, 
                                httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), 
                                samesite=os.getenv("COOKIE_SAMESITE"))
        except ExpiredRefreshTokenError:
            raise HTTPException(status_code=401, detail="refresh token expired. please login again")
    except Exception as e:
        raise HTTPException(status_code=401, detail="invalid access token cookie")
    