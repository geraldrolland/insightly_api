from fastapi import APIRouter, Body, Header, Query, Cookie
from fastapi.responses import RedirectResponse
from typing import Annotated
from pydantic import AfterValidator
from fastapi import status, Depends
from sqlmodel import Session, select
from insightly_api.dependencies import get_session
from insightly_api.dependencies import check_agreetoTermsandPolicy
from insightly_api.type import PasswordChangeType, UserLoginType, UserRegistrationType, validate_passwordmatch, TokenType
from fastapi.exceptions import HTTPException
from insightly_api.models import User
from insightly_api.utils import hash_password, verify_access_token, refresh_access_token, generate_verification_link
from insightly_api.tasks.email import send_verification_email
from dotenv import load_dotenv
import os
import uuid
from jwt.exceptions import InvalidTokenError, DecodeError, ExpiredSignatureError 
from insightly_api.exceptions import ExpiredRefreshTokenError
from insightly_api.main import redis_client

load_dotenv('.env')

auth_router = APIRouter(
    prefix="/api/v1/auth",
    tags=["users"],
)

@auth_router.post("/register",  status_code=status.HTTP_201_CREATED, description="allow user to register by providing email, password and confirm password for registraton")
async def register_user(data: Annotated[UserRegistrationType, AfterValidator(validate_passwordmatch), Depends(check_agreetoTermsandPolicy)], session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    user = session.exec(select(User).where(User.email == data.email)).first()
    if user:
        raise HTTPException(status_code=400, detail="user with this email already exists")
    user = User(email=data.email, hashed_password=hash_password(data.password), 
                agree_toTermsAndPolicy=data.agree_toTermsAndPolicy)
    session.add(user)
    session.commit()
    session.refresh(user)
    verification_link = generate_verification_link(data.email, "login")
    body = {"verification_link": verification_link}
    send_verification_email.delay(user.email, body)    
    return {"detail": "user registered successfully"}

@auth_router.post("/login", 
                  status_code=status.HTTP_200_OK, 
                  description="allow user to log in by providing email and password as authentication credential")
async def login_user(data: UserLoginType, session: Annotated[Session, Depends(get_session)]):
    user = session.exec(select(User).where(User.email == data.email)).first()
    if not user:
        raise HTTPException(status_code=400, detail="invalid email or password")
    if not hash_password(data.password) == user.hashed_password:
        raise HTTPException(status_code=400, detail="invalid email or password")
    if user.is_email_verified == False:
        raise HTTPException(status_code=400, detail="email not verified. please verify your email before logging in")
    return {"detail": "logged in successfully"}

@auth_router.get("/me", status_code=status.HTTP_200_OK, description="get currently logged in user details")
async def get_current_user(authorization: Annotated[str, Header()], session: Annotated[Session, Depends(get_session)]):
    access_token = authorization.split("")[-1]
    try:
        data = verify_access_token(access_token)
        email = data.get("email")
        user = session.exec(select(User).where(User.email == email)).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user does not exist")
        response = {
            "id": user.id,
            "email": user.email
        }
        return response
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token provided")
    except DecodeError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unable to decode token")
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expired token provided")

@auth_router.post("/reset-password", status_code=status.HTTP_200_OK, description="allow user to provide password and confirm password for password change")
async def reset_password(data: Annotated[PasswordChangeType, AfterValidator(validate_passwordmatch)], token: Annotated[str, Cookie()], session: Annotated[Session, Depends(get_session)]):
    email = redis_client.get(token)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="permission denied for password reset")
    user = session.exec(select(User).where(User.email == email)).first()
    hashed_pswd = hash_password(data.password)
    user.hashed_password = hashed_pswd
    session.add(user)
    session.commit()
    redis_client.delete(token)
    return {"detail": "password changed succesfully"}

@auth_router.post("/email", status_code=status.HTTP_200_OK, description="allow user to provide email for password change")
async def user_email(email: Annotated[str, Body(embed=True, pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$')], session: Annotated[Session, Depends(get_session)]):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user does not exist")
    verification_link = generate_verification_link(email, "reset-password")
    body = {"verification_link": verification_link}
    send_verification_email.delay(email, body)
    return {"detail": "verification link has been set to the email successfully"}

@auth_router.get("/verify-email", status_code=status.HTTP_307_TEMPORARY_REDIRECT, description="verifies user email from the provided token")
async def verify_email(query: Annotated[TokenType, Query()], session: Annotated[Session, Depends(get_session)]):
    email = redis_client.get(query.token)
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid or expired link provided")
    user = session.exec(select(User).where(User.email == email)).first()
    redis_client.delete(query.token)
    if not user.is_email_verified:
        user.is_email_verified = True
        session.add(user)
        session.commit()
    if query.next == "reset-password":
        # assign create token with the key token in the cookie and sign 
        pass

    redirect_url = f"{os.getenv("APP_HOST")}?next={query.next}"
    return RedirectResponse(redirect_url)

@auth_router.get("/refresh-token", status_code=status.HTTP_200_OK, description="allows users to refresh expired access token")
async def refresh_token(authorization: Annotated[str, Header()] = None):
    if not authorization:
        raise HTTPException(status_code=400, detail="Authorization header missing")
    access_token = authorization.split("")[-1]
    if not access_token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token missing in authorization header")
    try:
        access_token = refresh_access_token(access_token)
    except ExpiredRefreshTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="refresh token expired")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid token provided")
    except DecodeError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unable to decode token")
    
    return {"acess_token": access_token}
    
