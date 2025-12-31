import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from insightly_api.routers import auth, projects, google_auth
from insightly_api.routers import auth
import redis
from contextlib import asynccontextmanager


redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        decode_responses=True
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    from sqlmodel import SQLModel
    from .db_config import get_engine
    from .core.settings import settings

    if settings.ENVIRONMENT == "dev":
        SQLModel.metadata.create_all(get_engine())
    yield
    redis_client.close()


app = FastAPI(title="Insightly API Documentation")




origins = [
    "http://localhost:3000",
]

# app.add_middleware(CORSMiddleware(
#     app=app,
#     allow_origins=origins,
#     allow_methods=["*"],
#     allow_headers=["*"],
#     allow_credentials=True,
# ))

# routers
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(google_auth.router)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)