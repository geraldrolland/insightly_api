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
from insightly_api.utils import hash_password, verify_access_token, refresh_access_token, generate_verification_link, generate_access_token, generate_otp
from insightly_api.tasks.email import send_verification_email, send_otp_email
from dotenv import load_dotenv
import os
import uuid
from jwt.exceptions import InvalidTokenError, DecodeError, ExpiredSignatureError 
from insightly_api.exceptions import ExpiredRefreshTokenError


load_dotenv('.env')

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

@router.post("/register",  
                  status_code=status.HTTP_201_CREATED, description="allow user to register by providing email, password and confirm password for registraton")
async def register_user(data: Annotated[UserRegistrationType, AfterValidator(validate_passwordmatch), Depends(check_agreetoTermsandPolicy)], session: Annotated[Session, Depends(get_session)]):

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

@router.post("/login", 
                  status_code=status.HTTP_200_OK, 
                  description="allow user to log in by providing email and password as authentication credential")
async def login_user(data: UserLoginType, session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    user = session.exec(select(User).where(User.email == data.email)).first()
    if not user:
        raise HTTPException(status_code=400, detail="invalid email or password")
    if not hash_password(data.password) == user.hashed_password:
        raise HTTPException(status_code=400, detail="invalid email or password")
    if user.is_email_verified == False:
        verification_link = generate_verification_link(user.email, next="login")
        body = {"verification_link": verification_link}
        send_verification_email.delay(user.email, body)
        raise HTTPException(status_code=403, detail="a verification link has been sent your email. verify email email before logging in")
    if user.is_MFA_enabled:
        otp_code = generate_otp(length=6)
        key = str(uuid.uuid3())
        redis_client.set(name=key, value=otp_code, ex=2*60)
        # set key as otp_token in cookie 
        body = {"otp": otp_code}
        send_otp_email.delay(user.email, body)
        redirect_url = f"{os.getenv("APP_HOST")}/otp-verification"
        return RedirectResponse(redirect_url) 
        
    payload = {
        "id": user.id,
        "email": user.email
    }
    access_token = generate_access_token(payload)

    response = {
        "id": user.id,
        "email": user.email,
        "access_token": access_token
    }
    return response

@router.get("/me", status_code=status.HTTP_200_OK, description="get currently logged in user details")
async def get_current_user(Authorization: Annotated[str, Header()], 
                           session: Annotated[Session, Depends(get_session)]):
    access_token = Authorization.split("")[-1]
    bearer = Authorization.split("")[0]
    if bearer != "Bearer":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token must be a bearer type")
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

@router.post("/reset-password", 
                  status_code=status.HTTP_200_OK, description="allow user to provide password and confirm password for password change")
async def reset_password(data: Annotated[PasswordChangeType, AfterValidator(validate_passwordmatch)], 
                         token: Annotated[str, Cookie()], 
                         session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    email = redis_client.get(token)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="permission denied for a password reset")
    user = session.exec(select(User).where(User.email == email)).first()
    hashed_pswd = hash_password(data.password)
    user.hashed_password = hashed_pswd
    session.add(user)
    session.commit()
    redis_client.delete(token)
    return {"detail": "password changed succesfully"}

@router.post("/email", status_code=status.HTTP_200_OK, 
                  description="allow user to provide email for password change")
async def user_email(email: Annotated[str, Body(embed=True, pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$')], session: Annotated[Session, Depends(get_session)]):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user does not exist")
    verification_link = generate_verification_link(email, "reset-password")
    body = {"verification_link": verification_link}
    send_verification_email.delay(email, body)
    return {"detail": "verification link has been set to the email successfully"}


@router.get("/verify-email", status_code=status.HTTP_200_OK, description="verifies user email from the provided token")
async def verify_email(query: Annotated[TokenType, Query()], session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

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
        # add a token to cookie to allow password reset functionality
        pass
    return {"detail": "email verified successfully"}

@router.get("/refresh-token", status_code=status.HTTP_200_OK, description="allows users to refresh expired access token")
async def refresh_token(Authorization: Annotated[str, Header()]):
    access_token = Authorization.split("")[-1]
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
    
    return {"access_token": access_token}

@router.post("/verify-otp", status_code=200, description="verify the provided otp code")
def verify_otp(otp_code: Annotated[str, Body(embed=True)], 
               otp_token: Annotated[str, Cookie()], 
               email: Annotated[str, Cookie()], 
               session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    otp = redis_client.get(otp_token)
    if not otp:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="cannot process provided otp. otp expired")
    if otp != otp_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid otp provided")
    user = session.exec(select(User).where(User.email == email)).first()
    payload = {
        "id": user.id,
        "email": user.email
    }
    access_token = generate_access_token(payload)
    return {
        "id": user.id,
        "email": user.email,
        "access_token": access_token
    }

@router.get("/resend-otp", status_code=status.HTTP_200_OK, description="resend new otp to users")
def resend_otp(email: Annotated[str, Cookie()], 
               session: Annotated[Session, Depends(get_session)], 
               otp_token: Annotated[str, Cookie()]):
    from insightly_api.main import redis_client

    otp = redis_client.get(otp_token)
    if otp:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="cannot process. current otp code has not expired")
    user = session.exec(select(User).where(User.email == email)).first()
    otp_code = generate_otp(length=6)
    key = str(uuid.uuid3())
    redis_client.set(name=key, value=otp_code, ex=2*60)
    # set key with name otp_token in cookie
    body = {"otp": otp_code}
    send_otp_email.delay(user.email, body)
    return {"detail": "otp sent successfully"}

@router.get("/enable-MFA", status_code=status.HTTP_200_OK, description="enable multifactor authentication")
def enable_MFA():
    pass
    
@router.get("/disable-MFA", status_code=status.HTTP_200_OK, description="disable multifactor authentication")
def disable_MFA():
    pass

@router.get("/status-MFA", status_code=status.HTTP_200_OK, description="multifactor authentication status")
def status_MFA():
    pass
    

    
