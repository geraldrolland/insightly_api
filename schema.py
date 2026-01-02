from pydantic import BaseModel, Field, model_validator
from typing import Annotated, Literal, Union
from fastapi import UploadFile, File, Form
from pydantic import AfterValidator, ValidationInfo
import re


class BaseSchema(BaseModel):
    password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])
    confirm_password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])

    @model_validator(mode="after")
    def validate_passwordmatch(self):
        if not re.search(r"[a-z]", self.password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[A-Z]", self.password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"\d", self.password):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[^A-Za-z0-9]", self.password):
            raise ValueError("Password must contain at least one special character")
        if self.password != self.confirm_password:
            raise ValueError("password and confirm password do not match")
        return self
    
class UpdateUserSchema(BaseModel):
    email: str = Field(default=None, pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    password: str = Field(default=None, min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123$P"])
    confirm_password: str = Field(default=None, min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123$P"])

# user related types and validators
class UserRegistrationSchema(BaseSchema):
    model_config = {"extra": "forbid"}

    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    agree_toTermsAndPolicy: bool = Field(..., description="must be true to proceed with registration", examples=[True])
 
# user login and password change schemas
class UserLoginSchema(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])

class PasswordChangeSchema(BaseSchema):
    pass

class TokenSchema(BaseModel):
    model_config = {"extra": "forbid"}

    token: str
    next: str

class EmailSchema(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$')



class ProjectInfoSchema(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=100, description="project name must be between 1 and 100 characters", examples=["New Project"])
    description: str = Field(default=None, max_length=500, description="project description must not exceed 500 characters", examples=["This is a sample project description."])
    datasource_type: Literal["Database", "API", "File"] = Field(..., description="type of the data source", examples=["Api"])

class FileUploadSchema(ProjectInfoSchema):
    model_config = {"extra": "forbid"}
    file_type: Literal["csv", "txt", "json", "xlsx"] = Field(..., description="type of the file being uploaded", examples=["csv"])
    file: Annotated[UploadFile, File(..., description="file to be uploaded must be of the following file extensions - csv, txt, json, xlsx")]

    @model_validator(mode="after")
    def validate_file(self):
        allowed_file_extensions = ("csv", "txt", "json", "xlsx")
        if self.file.filename.split(".")[-1].lower() not in allowed_file_extensions:
            raise ValueError(f"Unsupported file type: {self.file.filename.split('.')[-1]}. Allowed types are: {', '.join(allowed_file_extensions)}")
        return self

class DatabaseConnectionSchema(ProjectInfoSchema):
    model_config = {"extra": "forbid"}

    db_type: Literal["postgresql", "mysql", "sqlite"] = Field(..., description="type of the database", examples=["postgresql"])
    username: str = Field(..., description="database username", examples=["dbuser"])
    password: str = Field(..., description="database password", examples=["strongpassword123$P"])
    database_name: str = Field(..., description="name of the database", examples=["mydatabase"])
    host: str = Field(..., description="database host address", examples=["localhost", "127.0.0.1"])
    query: str = Field(..., description="valid sql query statement", examples=["SELECT * FROM users;"])

    @model_validator(mode="after")
    def validate_query(self):
        from insightly_api.core.settings import settings

        query = self.query.strip()

        # 1️⃣ Enforce query length (prevents abuse / DoS)
        if len(query) > 10_000:
            raise ValueError("SQL query is too long.")

        # 2️⃣ Remove SQL comments (inline and block)
        query_no_comments = re.sub(r'--.*?$', '', query, flags=re.MULTILINE)
        query_no_comments = re.sub(r'/\*.*?\*/', '', query_no_comments, flags=re.DOTALL)

        # 3️⃣ Prevent multiple SQL statements
        if ";" in query_no_comments:
            raise ValueError("Multiple SQL statements are not allowed.")

        # 4️⃣ Ensure query starts with SELECT only
        if not re.match(r'^\s*SELECT\b', query_no_comments, re.IGNORECASE):
            raise ValueError("Only SELECT statements are allowed.")

        # 5️⃣ Block forbidden SQL keywords anywhere
        excluded_keywords = settings.ALL_EXCLUDED_SQL_KEYWORDS

        forbidden_pattern = re.compile(
            r'\b(' + '|'.join(map(re.escape, excluded_keywords)) + r')\b',
            re.IGNORECASE
        )

        if forbidden_pattern.search(query_no_comments):
            raise ValueError(
                "The SQL query contains forbidden operations. Only SELECT statements are allowed."
            )

        return self


class APIIntegrationSchema(ProjectInfoSchema):
    model_config = {"extra": "forbid"}

    name: str = Field(default=None, min_length=1, max_length=100, description="API integration name must be between 1 and 100 characters", examples=["My API Integration"])
    api_url: str = Field(..., description="URL of the api", examples=["https://api.example.com/endpoint"])
    is_auth_required: bool = Field(..., description="indicates if the API requires authentication", examples=[True])
    Auth_headers: dict[str, str] | None = Field(default=None, description="optional headers to include in the API request", examples=[{"Authorization": "Bearer your_api_key_here"}])

    @model_validator(mode="after")
    def validate_auth_headers(self):
        if self.is_auth_required and not self.Auth_headers:
            raise ValueError("Auth_headers must be provided if is_auth_required is True")
        return self

DataConfigType = Union[APIIntegrationSchema, DatabaseConnectionSchema]