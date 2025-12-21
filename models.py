from sqlmodel import Field, SQLModel
from datetime import timezone, datetime
from sqlalchemy import func
from enum import Enum

class SourceType(str, Enum):
    file = "file"
    database = "database"
    api = "api"

class DataSetStatus(str, Enum):
    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    agree_toTermsAndPolicy: bool
    is_active: bool = Field(default=True)
    is_email_verified: bool = Field(default=False)
    is_MFA_enabled: bool =  Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column_kwargs={"onupdate": func.now(timezone.utc)})

    def __repr__(self):
        return f"User(id={self.id}, email={self.email}, is_active={self.is_active}, is_email_verified={self.is_email_verified})"


class Project(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str
    datasource_type: SourceType
    csv_datafile: str | None = None
    is_data_ready: bool = Field(default=False)
    owner: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column_kwargs={"onupdate": func.now(timezone.utc)})

    def __repr__(self):
        return f"Project(id={self.id}, name={self.name}, datasource_type={self.datasource_type})"

class DataSet(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    status: DataSetStatus = Field(default=DataSetStatus.IN_PROGRESS)
    num_of_records: int = Field(default=0, ge=0)
    project: int = Field(foreign_key="project.id", unique=True)
    owner: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), sa_column_kwargs={"onupdate": func.now(timezone.utc)})

class DataSetRow(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: int
    dataset: int = Field(foreign_key="dataset.id")