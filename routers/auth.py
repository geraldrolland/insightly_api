from fastapi import APIRouter, Body, Header, Query
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
from insightly_api.utils import hash_password, verify_access_token
from insightly_api.tasks.email import send_verification_email
from dotenv import load_dotenv
import os
import uuid
from jwt.exceptions import InvalidTokenError, DecodeError, ExpiredSignatureError 

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
    token = str(uuid.uuid4())
    redis_client.set(token, user.email, ex=7*60)
    verification_link = f"{os.getenv('APP_HOST')}/verify-email?token={token}"
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
async def reset_password(data: Annotated[PasswordChangeType, AfterValidator(validate_passwordmatch)]):
    return {"detail": "password changed succesfully"}

@auth_router.post("/email", status_code=status.HTTP_200_OK, description="allow user to provide email for password change")
async def user_email(email: Annotated[str, Body(embed=True, pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$'),]):
    return {"detail": "verification link has been set to the email successfully"}

@auth_router.post("/verify-email", status_code=status.HTTP_200_OK, description="verifies user email from the provided token")
async def otp_verification(query: Annotated[TokenType, Query()]):
    return {"detail": "otp verified successfully"}

@auth_router.get("/refresh-token", status_code=status.HTTP_200_OK, description="allows users to refresh expired access token")
async def refresh_token(authorization: Annotated[str, Header()] = None):
    if not authorization:
        raise HTTPException(status_code=400, detail="access token missing in Authorization header")
    
