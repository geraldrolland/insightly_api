import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from insightly_api.routers import auth, projects
from insightly_api.routers import auth
import redis



app = FastAPI(title="Insightly API Documentation")

redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        decode_responses=True
    )


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

@app.on_event("startup")
def on_startup():
    from sqlmodel import SQLModel
    from .db_config import get_engine
    from dotenv import load_dotenv
    import os

    load_dotenv(".env")

    if os.getenv("ENVIRONMENT") == "dev":
        SQLModel.metadata.create_all(get_engine())



@app.on_event("shutdown")
def on_shutdown():

    # close redis connection
    redis_client.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)