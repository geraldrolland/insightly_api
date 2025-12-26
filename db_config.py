from sqlmodel import create_engine, SQLModel
from insightly_api.core.settings import settings


sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
postgresql_url = "postgresql+psycopg2://dev:123@localhost/db_dev"
postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"
connect_args = {"check_same_thread": False}

def get_engine():
    engine = None

    if settings.ENVIRONMENT == "dev":
        engine = create_engine(postgresql_url, future=True)
    elif settings.ENVIRONMENT == "test":
        engine = create_engine(postgresql_test_url, future=True)
    
    return engine
