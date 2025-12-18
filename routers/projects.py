from fastapi import APIRouter

project_router = APIRouter(
    prefix="/api/v1/projects",
    tags=["projects"],
)
