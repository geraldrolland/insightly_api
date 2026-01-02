from fastapi import APIRouter, Query, Header
from fastapi.responses import RedirectResponse
from typing import Annotated
from fastapi import status, Depends
from sqlmodel import Session
from insightly_api.dependencies import get_session
from insightly_api.utils import  generate_access_token, sign_cookie
from insightly_api.core.settings import settings
from fastapi import Request
from insightly_api.services.google_service import login_with_google



router = APIRouter(
    prefix="/api/v1/google-auth",
    tags=["auth"],
)

@router.get("", status_code=status.HTTP_307_TEMPORARY_REDIRECT, description="This allows user to register or login with google account")
def google_auth(
                state: Annotated[str, Query()], 
                session: Annotated[Session, Depends(get_session)],
                user_agent: Annotated[str, Header()],
                code: Annotated[str, Query()] = None,
                error: Annotated[str, Query()] = None,
                ):
    if not state:
        return RedirectResponse(url=f"{settings.APP_HOST}?msg=google authentication failed", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    if error or not code:
        return RedirectResponse(url=f"{settings.APP_HOST}?msg=google authentication failed", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    try:
        user = login_with_google(code, session)
    except Exception as e:
        return RedirectResponse(url=f"{settings.APP_HOST}?msg=google authentication failed&auth_state={state}", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response = RedirectResponse(url=f"{settings.APP_HOST}/dashboard/projects?msg=google authentication success", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    access, refresh = generate_access_token({"email": user.email, "id": user.id, "user-agent": user_agent})
    value = sign_cookie({"access_token": access, "refresh_token": refresh})
    response.set_cookie(key="auth_token", 
                        value=value, 
                        httponly=True, secure=settings.COOKIE_SECURE, 
                        samesite=settings.COOKIE_SAMESITE)
    return response
