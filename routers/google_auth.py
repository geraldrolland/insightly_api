from fastapi import APIRouter, Body, Query, Cookie, Response
from fastapi.responses import RedirectResponse
from typing import Annotated
from fastapi import status, Depends
from sqlmodel import Session, select
from insightly_api.dependencies import get_session
from insightly_api.dependencies import check_agreetoTermsandPolicy, authenticate_user
from insightly_api.type import PasswordChangeType, UserLoginType, UserRegistrationType, TokenType
from fastapi.exceptions import HTTPException
from insightly_api.models.user_model import User
from insightly_api.utils import hash, verify_access_token, generate_verification_link, generate_access_token, generate_otp, verify_hash, sign_cookie, verify_signed_cookie
from insightly_api.tasks.email import send_verification_email, send_otp_email, send_welcome_email
from insightly_api.core.settings import settings
import uuid
from fastapi import Request
from insightly_api.services.google_service import login_with_google



router = APIRouter(
    prefix="/api/v1/google-auth",
    tags=["auth"],
)

@router.get("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT, description="This allows user to register or login with google account")
def google_auth(request: Request, session: Annotated[Session, Depends(get_session)]):
    params = request.query_params
    code = params.get("code")
    error = params.get("error")
    state = params.get("state")
    current = None
    next = None
    if not state:
        return RedirectResponse(url=f"{settings.FRONTEND_HOST}?google_auth=failed", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    current, next = state.split("|")
    if not current or not next:
        return RedirectResponse(url=f"{settings.FRONTEND_HOST}?google_auth=failed", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    if error or not code:
        return RedirectResponse(url=f"{settings.FRONTEND_HOST}?auth_state={current}&google_auth=failed", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    try:
        user = login_with_google(code, session)
    except Exception as e:
        return RedirectResponse(url=f"{settings.FRONTEND_HOST}?auth_state={current}&google_auth=failed", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response = RedirectResponse(url=f"{settings.FRONTEND_HOST}?auth_state={next}&google_auth=success", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    access, refresh = generate_access_token({"email": user.email})
    value = sign_cookie({"access_token": access, "refresh_token": refresh})
    response.set_cookie(key="auth_token", 
                        value=value, 
                        httponly=True, secure=settings.COOKIE_SECURE, 
                        samesite=settings.COOKIE_SAMESITE)
    return response