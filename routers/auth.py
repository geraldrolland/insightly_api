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
from insightly_api.utils import hash, verify_access_token, refresh_access_token, generate_verification_link, generate_access_token, generate_otp, verify_hash, sign_cookie, verify_signed_cookie
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
    user = User(email=data.email, hashed_password=hash(data.password), 
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
    import json

    user = session.exec(select(User).where(User.email == data.email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="invalid email or password")
    if not verify_hash(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid email or password")
    if user.is_email_verified == False:
        verification_link = generate_verification_link(user.email, next="login")
        body = {"verification_link": verification_link}
        send_verification_email.delay(user.email, body)
        raise HTTPException(status_code=403, detail="a verification link has been sent your email. verify email email before logging in")
    if user.is_MFA_enabled:
        otp_code = generate_otp(length=6)
        key = str(uuid.uuid4())
        redis_client.set(name=key, value=json.dumps({"otp_code": otp_code, "attempts": 0}), ex=2*60)
        payload = {
            "email": user.email,
            "otp_token": key
        }
        value = sign_cookie(payload)
        body = {"otp": otp_code}
        send_otp_email.delay(user.email, body)
        redirect_url = f"{os.getenv("APP_HOST")}?auth_state=otp-verification"
        response = RedirectResponse(redirect_url)
        response.set_cookie(key="otp_ctx", 
                            value=value, 
                            httponly=True, 
                            secure=bool(os.getenv("COOKIE_SECURE")), 
                            samesite=os.getenv("COOKIE_SAMESITE"),
                            )
        return response
    
    payload = {
        "id": user.id,
        "email": user.email
    }
    access_token, refresh_token = generate_access_token(payload)

    response.set_cookie(key="auth_token", 
                        value=sign_cookie({"access_token": access_token, "refresh_token": refresh_token}),
                        httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), 
                        samesite=os.getenv("COOKIE_SAMESITE"))

    return {"detail": "user logged in successfully"}


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
    hashed_pswd = hash(data.password)
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
               otp_ctx: Annotated[str, Cookie()], 
               response: Response,
               session: Annotated[Session, Depends(get_session)]):
    from insightly_api.main import redis_client
    import json

    try:
        payload = verify_signed_cookie(otp_ctx, max_age=None)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="cannot verify otp. otp context expired")

    value = json.loads(redis_client.get(payload.get("otp_token")))
    email = payload.get("email")
    if not value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="cannot process provided otp. otp expired")
    if value.get("otp_code") != otp_code:
        value["attempts"] += 1
        redis_client.set(name=payload.get("otp_token"), value=json.dumps(value), ex=2*60)
        if value["attempts"] >= 3:
            redis_client.delete(payload.get("otp_token"))
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="maximum otp verification attempts exceeded. generate new otp to proceed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid otp provided")
    user = session.exec(select(User).where(User.email == email)).first()

    

    redis_client.delete(payload.get("otp_token"))
    response.set_cookie(key="otp_ctx", value="", expires=0)

    payload = {
        "id": user.id,
        "email": user.email
    }
    access_token, refresh_token = generate_access_token(payload)
    response.set_cookie(key="auth_token", 
                        value=sign_cookie({"access_token": access_token, "refresh_token": refresh_token}),
                        httponly=True, secure=bool(os.getenv("COOKIE_SECURE")), 
                        samesite=os.getenv("COOKIE_SAMESITE"))
    return {"detail": "otp verified successfully"}

@router.get("/resend-otp", status_code=status.HTTP_200_OK, description="resend new otp to users")
def resend_otp(response: Response,
               session: Annotated[Session, Depends(get_session)], 
               otp_ctx: Annotated[str, Cookie()]):
    from insightly_api.main import redis_client
    import json

    try:
        payload = verify_signed_cookie(otp_ctx, max_age=None)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="cannot resend otp. otp context expired")
    otp = redis_client.get(payload.get("otp_token"))
    if otp:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="cannot process. current otp code has not expired")
    user = session.exec(select(User).where(User.email == payload.get("email"))).first()
    if user.is_MFA_enabled == False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="multifactor authentication is not enabled for this user")
    otp_code = generate_otp(length=6)
    key = str(uuid.uuid4())
    payload["otp_token"] = key
    redis_client.set(name=key, value=json.dumps({"otp_code": otp_code, "attempts": 0}), ex=2*60)
    response.set_cookie(key="otp_ctx", 
                        value=sign_cookie(payload), 
                        httponly=True, 
                        secure=bool(os.getenv("COOKIE_SECURE")), 
                        samesite=os.getenv("COOKIE_SAMESITE"),
                        )
    body = {"otp": otp_code}
    send_otp_email.delay(user.email, body)
    return {"detail": "otp sent successfully"}

@router.get("/enable-mfa", 
            status_code=status.HTTP_200_OK, 
            description="enable multifactor authentication",
            dependencies=[Depends(authenticate_user)]
            )
def enable_mfa(request: Request, session: Annotated[Session, Depends(get_session)]):
    user = request.state.auth_user
    if user.is_MFA_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="multifactor authentication is already enabled for this user")
    user.is_MFA_enabled = True
    session.add(user)
    session.commit()
    return {"detail": "multifactor authentication enabled successfully"}
    
    
@router.get("/disable-mfa", 
            status_code=status.HTTP_200_OK, 
            description="disable multifactor authentication",
            dependencies=[Depends(authenticate_user)]
            )
def disable_mfa(request: Request, session: Annotated[Session, Depends(get_session)]):
    user = request.state.auth_user
    if not user.is_MFA_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="multifactor authentication is already disabled for this user")
    user.is_MFA_enabled = False
    session.add(user)
    session.commit()
    return {"detail": "multifactor authentication disabled successfully"}

@router.get("/status-mfa", 
            status_code=status.HTTP_200_OK, 
            description="multifactor authentication status",
            dependencies=[Depends(authenticate_user)]
            )
def status_mfa(request: Request):
    user = request.state.auth_user
    return {"is_MFA_enabled": user.is_MFA_enabled}

@router.get("/logout", 
            status_code=status.HTTP_200_OK, 
            description="log out currently logged in user by deleting access token cookie",
            dependencies=[Depends(authenticate_user)]
            )
def logout_user(request: Request, response: Response):
    from insightly_api.main import redis_client
    refresh_token = redis_client.get(verify_signed_cookie(request.cookies.get("access_token")))
    redis_client.delete(refresh_token)
    redis_client.delete(verify_signed_cookie(request.cookies.get("access_token")))
    response.delete_cookie(key="access_token")
    return {"detail": "user logged out successfully"}
    

    
