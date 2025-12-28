from sqlmodel import Field, SQLModel
from datetime import timezone, datetime
from sqlalchemy import func
from enum import Enum
from sqlalchemy import Column, Index
from sqlalchemy.dialects.postgresql import JSONB


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str = Field(nullable=False)
    agree_toTermsAndPolicy: bool
    is_active: bool = Field(default=True)
    is_email_verified: bool = Field(default=False)
    is_MFA_enabled: bool =  Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
        sa_column_kwargs={"server_default": func.now(), "onupdate": func.now(), "nullable": False}
    )

    def __repr__(self):
        return f"User(id={self.id}, email={self.email}, is_active={self.is_active}, is_email_verified={self.is_email_verified})"


# Index(
#     "ix_datarowset_metadata_gin",
#     DataSetRow.__table__.c.data,
#     postgresql_using="gin",
# )