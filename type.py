from pydantic import BaseModel, Field
from typing import Annotated, Literal
from fastapi import UploadFile, File, Form
from pydantic import AfterValidator
import re


def validate_otp(otp):
    if len(otp) != 6:
        raise ValueError("otp must be 6 digit in lenght")
    return otp


def validate_CSVFile(file: UploadFile):
    if file.filename.split(".")[-1] != "csv":
        raise ValueError("file must a valid csv file")
    return file

def validate_SQLFile(file: UploadFile):
    if file.filename.split(".")[-1] != "sql":
        raise ValueError("file must be a valid sql file")
    return file


class DatabaseType(BaseModel):
    model_config = {"extra": "forbid"}

    username: str
    password: str
    connection_string: str
    query_type: Literal["uploadSQLFile", "writeQuery"]
    write_query: str | None = None
    uploadSQLFile: Annotated[UploadFile | None, File(), AfterValidator(validate_SQLFile)]

def validate_databasetype(database: DatabaseType):
    if database.uploadSQLFile is not None and database.write_query is not None:
        raise ValueError("cannot provided both uploadSQLFile and write_query at the same time")
    elif database.query_type == "uploadSQLFile":
        if database.uploadSQLFile is None:
            raise ValueError("sql file must provided when query_type is uploadSQLFile")
    elif database.query_type == "writeQuery":
        if database.write_query is None:
            raise ValueError("query must be provided when the query_type is writeQuery")
    return database

class APIType(BaseModel):
    model_config = {"extra": "forbid"}

    api_url: str
    is_authenticated: bool = Field(default=False)
    authentication_type: Literal["apikey", "access_token"]
    access_token: str | None = None
    apikey: str | None = None

def validate_apitype(api: APIType):
    if api.access_token is not None and api.apikey is not None:
        raise ValueError("cannot provide both apikey and accesstoken")
    elif api.authentication_type == "apikey":
        if api.apikey is None:
            raise ValueError("apikey must be provided when authentication type is apikey")  
    elif api.authentication_type == "access_token":
        if api.access_token is None:
            raise ValueError("access token must provided when authentication type is access token")
    return api

class ProjectType(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=3)
    description: str = Field(..., min_length=3)
    datasource_type: Literal["file", "database", "api"]

class BaseUser(BaseModel):
    password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])
    confirm_password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])

# user related types and validators
class UserRegistrationType(BaseUser):
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    agree_toTermsAndPolicy: bool = Field(..., description="must be true to proceed with registration", examples=[True])

def validate_registration(data: BaseUser):
    if not re.search(r"[a-z]", data.password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[A-Z]", data.password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"\d", data.password):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[^A-Za-z0-9]", data.password):
        raise ValueError("Password must contain at least one special character")
    if data.password != data.confirm_password:
        raise ValueError("password and confirm password do not match")
    return data
 
# user login and password change types
class UserLoginType(BaseModel):
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])

class PasswordChangeType(BaseUser):
    pass

