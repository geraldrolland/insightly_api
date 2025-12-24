from fastapi import APIRouter, Body, Header, Query, Cookie, Response
from fastapi.responses import RedirectResponse
from typing import Annotated

from fastapi import status, Depends
from sqlmodel import Session, select
from insightly_api.dependencies import get_session
from insightly_api.dependencies import check_agreetoTermsandPolicy, authenticate_user
from insightly_api.type import PasswordChangeType, UserLoginType, UserRegistrationType, TokenType
from fastapi.exceptions import HTTPException
from insightly_api.models.user_model import User
from insightly_api.utils import hash_password, verify_access_token, refresh_access_token, generate_verification_link, generate_access_token, generate_otp, verify_password, sign_cookie, verify_signed_cookie
from insightly_api.tasks.email import send_verification_email, send_otp_email, send_welcome_email
from dotenv import load_dotenv
import os
import uuid
from jwt.exceptions import InvalidTokenError, DecodeError, ExpiredSignatureError 
from insightly_api.exceptions import ExpiredRefreshTokenError
from fastapi import Request

load_dotenv('.env')

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

@router.post("/register",  
                  status_code=status.HTTP_201_CREATED, description="allow user to register by providing email, password and confirm password for registraton")
async def register_user(data: Annotated[UserRegistrationType, Depends(check_agreetoTermsandPolicy)], 
                        session: Annotated[Session, Depends(get_session)]):

    user = session.exec(select(User).where(User.email == data.email)).first()
    if user:
        raise HTTPException(status_code=400, detail="user with this email already exists")
    user = User(email=data.email, hashed_password=hash_password(data.password), 
                agree_toTermsAndPolicy=data.agree_toTermsAndPolicy)
    session.add(user)
    session.commit()
    session.refresh(user)
    send_welcome_email.delay(user.email)   
    return {"detail": "user registered successfully"}

@router.post("/login", 
                  status_code=status.HTTP_200_OK, 
                  description="allow user to log in by providing email and password as authentication credential")
async def login_user(data: UserLoginType, 
                     response: Response, 
                     session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    user = session.exec(select(User).where(User.email == data.email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="invalid email or password")
    if not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid email or password")
    if user.is_email_verified == False:
        verification_link = generate_verification_link(user.email, next="login")
        body = {"verification_link": verification_link}
        send_verification_email.delay(user.email, body)
        raise HTTPException(status_code=403, detail="a verification link has been sent your email. verify email email before logging in")
    if user.is_MFA_enabled:
        otp_code = generate_otp(length=6)
        key = str(uuid.uuid4())
        redis_client.set(name=key, value=otp_code, ex=2*60)
        # set key as otp_token in cookie 
        body = {"otp": otp_code}
        send_otp_email.delay(user.email, body)
        redirect_url = f"{os.getenv("APP_HOST")}?auth_state=otp-verification"
        response = RedirectResponse(redirect_url)
        response.set_cookie(key="otp_token", 
                            value=key, 
                            httponly=True, 
                            secure=bool(os.getenv("COOKIE_SECURE")), 
                            samesite=os.getenv("COOKIE_SAMESITE"),
                            max_age=120
                            )

        response.set_cookie(key="email", 
                            value=user.email, 
                            httponly=True, 
                            secure=bool(os.getenv("COOKIE_SECURE")), 
                            samesite=os.getenv("COOKIE_SAMESITE"))
        return response
    
    payload = {
        "id": user.id,
        "email": user.email
    }
    access_token = generate_access_token(payload)

    response.set_cookie(key="access_token", 
                        value=sign_cookie(access_token),
                        httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), 
                        samesite=os.getenv("COOKIE_SAMESITE"))

    return {
        "id": user.id,
        "email": user.email,
    }


@router.get("/me", 
            status_code=status.HTTP_200_OK, 
            description="get currently logged in user details",
            dependencies=[Depends(authenticate_user)]
            )
async def get_current_user(request: Request):
    response = {
        "id": request.state.auth_user.id,
        "email": request.state.auth_user.email,
    }
    return response

@router.post("/reset-password", 
                  status_code=status.HTTP_200_OK, 
                  description="allow user to provide password and confirm password for password change")
async def reset_password(data: Annotated[PasswordChangeType, Body()], 
                         allow_pswd_reset_token: Annotated[str, Cookie()], 
                         session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    try:
        allow_pswd_reset_token = verify_signed_cookie(allow_pswd_reset_token, max_age=10*60)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="permission denied for a password reset from max age")
    email = redis_client.get(allow_pswd_reset_token)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="permission denied for a password reset")
    user = session.exec(select(User).where(User.email == email)).first()
    hashed_pswd = hash_password(data.password)
    user.hashed_password = hashed_pswd
    session.add(user)
    session.commit()
    redis_client.delete(allow_pswd_reset_token)
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
async def verify_email(query: Annotated[TokenType, Query()],
                       session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client

    email = redis_client.get(query.token)
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid or expired link provided")
    user = session.exec(select(User).where(User.email == email)).one()
    redis_client.delete(query.token)
    user.is_email_verified = True
    session.add(user)
    session.commit()
        
    if query.next == "reset-password":
        password_reset_token = str(uuid.uuid4())
        signed_password_reset_token = sign_cookie(password_reset_token)
        redis_client.set(name=password_reset_token, value=email, ex=10*60)
        redirect_url = f"{os.getenv('APP_HOST')}?auth_state=reset-password"
        response = RedirectResponse(redirect_url)
        response.set_cookie(key="allow_pswd_reset_token", value=signed_password_reset_token, httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), samesite=os.getenv("COOKIE_SAMESITE"))
        return response
    
    return {"detail": "email verified successfully"}


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
               response: Response, 
               session: Annotated[Session, Depends(get_session)], 
               otp_token: Annotated[str, Cookie()]):
    from insightly_api.main import redis_client

    otp = redis_client.get(otp_token)
    if otp:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="cannot process. current otp code has not expired")
    user = session.exec(select(User).where(User.email == email)).first()
    if user.is_MFA_enabled == False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="multifactor authentication is not enabled for this user")
    otp_code = generate_otp(length=6)
    key = str(uuid.uuid4())
    redis_client.set(name=key, value=otp_code, ex=2*60)
    response.set_cookie(key="otp_token", 
                        value=key, 
                        httponly=True, 
                        secure=bool(os.getenv("COOKIE_SECURE")), 
                        samesite=os.getenv("COOKIE_SAMESITE"))
    body = {"otp": otp_code}
    send_otp_email.delay(user.email, body)
    return {"detail": "otp sent successfully"}

@router.get("/enable-MFA", 
            status_code=status.HTTP_200_OK, 
            description="enable multifactor authentication",
            dependencies=[Depends(authenticate_user)]
            )
def enable_MFA(request: Request, session: Annotated[Session, Depends(get_session)]):
    user = request.state.auth_user
    if user.is_MFA_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="multifactor authentication is already enabled for this user")
    user.is_MFA_enabled = True
    session.add(user)
    session.commit()
    return {"detail": "multifactor authentication enabled successfully"}
    
    
@router.get("/disable-MFA", status_code=status.HTTP_200_OK, description="disable multifactor authentication")
def disable_MFA(request: Request, session: Annotated[Session, Depends(get_session)]):
    user = request.state.auth_user
    if not user.is_MFA_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="multifactor authentication is already disabled for this user")
    user.is_MFA_enabled = False
    session.add(user)
    session.commit()
    return {"detail": "multifactor authentication disabled successfully"}

@router.get("/status-MFA", status_code=status.HTTP_200_OK, description="multifactor authentication status")
def status_MFA(request: Request):
    user = request.state.auth_user
    return {"is_MFA_enabled": user.is_MFA_enabled}

@router.get("/logout", 
            status_code=status.HTTP_200_OK, 
            description="log out currently logged in user by deleting access token cookie")
def logout_user(request: Request, response: Response):
    from insightly_api.main import redis_client
    refresh_token = redis_client.get(verify_signed_cookie(request.cookies.get("access_token")))
    redis_client.delete(refresh_token)
    redis_client.delete(verify_signed_cookie(request.cookies.get("access_token")))
    response.delete_cookie(key="access_token")
    return {"detail": "user logged out successfully"}
    

    
