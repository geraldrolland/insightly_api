from fastapi import APIRouter, Body, Query, Cookie, Response, Form, Path
from fastapi.responses import RedirectResponse
from typing import Annotated
from fastapi import status, Depends
from pydantic import AfterValidator
from sqlmodel import Session, select
from insightly_api.dependencies import get_session
from insightly_api.dependencies import check_agreetoTermsandPolicy, authenticate_user
from insightly_api.schema import ProjectInfoSchema, FileUploadSchema, DatabaseConnectionSchema, APIIntegrationSchema, DataConfigType
from fastapi.exceptions import HTTPException
from insightly_api.models.user_model import User
from insightly_api.utils import hash, verify_access_token, generate_verification_link, generate_access_token, generate_otp, verify_hash, sign_cookie, verify_signed_cookie
from insightly_api.tasks.email import send_verification_email, send_otp_email, send_welcome_email
from insightly_api.core.settings import settings
import uuid
from fastapi import Request



router = APIRouter(
    prefix="/api/v1/project",
    tags=["auth"],
    dependencies=[Depends(authenticate_user)]
)

@router.post("/create", status_code=status.HTTP_201_CREATED, description="create a new project for the authenticated user")
async def create_project(
                        session: Annotated[Session, Depends(get_session)],
                        request: Request,
                        dataconfig: Annotated[DataConfigType, Body(...)]
                         ):
    pass

@router.get("/list", status_code=status.HTTP_200_OK, description="List all projects for the authenticated user")
async def list_projects(session: Annotated[Session, Depends(get_session)], request: Request):
    pass

@router.get("/detail/{project_id}", status_code=status.HTTP_200_OK, description="Get a project by its ID")
async def get_project(project_id: Annotated[str, Path()], session: Annotated[Session, Depends(get_session)], request: Request):
    pass

@router.post("/delete/{project_id}", status_code=status.HTTP_200_OK, description="Delete a project by its ID")
async def delete_project(project_id: Annotated[str, Path()], session: Annotated[Session, Depends(get_session)], request: Request):
    pass