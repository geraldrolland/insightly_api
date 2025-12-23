# from sqlmodel import Field, SQLModel
# from datetime import timezone, datetime
# from sqlalchemy import func
# from enum import Enum
# from sqlalchemy import Column, Index
# from sqlalchemy.dialects.postgresql import JSONB


# class SourceType(str, Enum):
#     file = "file"
#     database = "database"
#     api = "api"

# class DataSetStatus(str, Enum):
#     COMPLETED = "completed"
#     IN_PROGRESS = "in_progress"

# class Project(SQLModel, table=True):
#     id: int | None = Field(default=None, primary_key=True)
#     name: str = Field(index=True, unique=True)
#     description: str
#     datasource_type: SourceType
#     csv_datafile: str | None = None
#     is_data_ready: bool = Field(default=False)
#     owner: int = Field(foreign_key="user.id")
#     created_at: datetime = Field(
#         default_factory=datetime.utcnow,
#         sa_column_kwargs={"server_default": func.now(), "nullable": False}
#     )
#     updated_at: datetime = Field(
#         default_factory=datetime.utcnow,
#         sa_column_kwargs={"server_default": func.now(), "onupdate": func.now(), "nullable": False}
#     )

#     def __repr__(self):
#         return f"Project(id={self.id}, name={self.name}, datasource_type={self.datasource_type})"
    
# class DataSet(SQLModel, table=True):
#     id: int = Field(default=None, primary_key=True)
#     status: DataSetStatus = Field(default=DataSetStatus.IN_PROGRESS)
#     num_of_records: int = Field(default=0, ge=0)
#     project: int = Field(foreign_key="project.id", unique=True)
#     owner: int = Field(foreign_key="user.id")
#     created_at: datetime = Field(
#         default_factory=datetime.utcnow,
#         sa_column_kwargs={"server_default": func.now(), "nullable": False}
#     )
#     updated_at: datetime = Field(
#         default_factory=datetime.utcnow,
#         sa_column_kwargs={"server_default": func.now(), "onupdate": func.now(), "nullable": False}
#     )

# class DataSetRow(SQLModel, table=True):
#     id: int = Field(default=None, primary_key=True)
#     created_at: datetime = Field(
#         default_factory=datetime.utcnow,
#         sa_column_kwargs={"server_default": func.now(), "nullable": False}
#     )
#     #data: dict[str, any] = Field(sa_column=JSONB)
#     dataset: int = Field(foreign_key="dataset.id")
