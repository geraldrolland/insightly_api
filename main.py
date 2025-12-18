import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from insightly_api.routers import auth, projects
from insightly_api.routers import auth
import redis


app = FastAPI()

redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        decode_responses=True
    )

SECRET_KEY = "3817feba54774215989d0dc1c08314073a00fdac83543e70621c6daf08d34563"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15



# routers
app.include_router(auth.auth_router)
app.include_router(projects.project_router)

@app.on_event("startup")
def on_startup():
    from .db_config import create_db_and_tables

    # create database and tables
    create_db_and_tables()

    # initialize redis client


@app.on_event("shutdown")
def on_shutdown():

    # close redis connection
    redis_client.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)