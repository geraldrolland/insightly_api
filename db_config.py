from sqlmodel import create_engine, SQLModel

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
postgresql_url = "postgresql+psycopg2://dev:123@localhost/db_dev"
connect_args = {"check_same_thread": False}
engine = create_engine(postgresql_url)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)