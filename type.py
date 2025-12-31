from pydantic import BaseModel, Field, model_validator
from typing import Annotated, Literal
from fastapi import UploadFile, File, Form
from pydantic import AfterValidator, ValidationInfo
import re


def validate_otp(otp: str):
    if len(otp) != 6:
        raise ValueError("otp must be 6 digit in length")
    elif not otp.isdigit():
        raise ValueError("otp must be in digits")
    return otp

class BaseUser(BaseModel):
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
    
class UpdateUserType(BaseModel):
    email: str = Field(default=None, pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    password: str = Field(default=None, min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123$P"])
    confirm_password: str = Field(default=None, min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123$P"])

# user related types and validators
class UserRegistrationType(BaseUser):
    model_config = {"extra": "forbid"}

    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    agree_toTermsAndPolicy: bool = Field(..., description="must be true to proceed with registration", examples=[True])
 
# user login and password change types
class UserLoginType(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', description="must be a valid email address", examples=["user@example.com"])
    password: str = Field(..., min_length=8, description="password must be at least 8 characters long", examples=["strongpassword123"])

class PasswordChangeType(BaseUser):
    pass

class TokenType(BaseModel):
    model_config = {"extra": "forbid"}

    token: str
    next: str

class EmailType(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$')

class GoogleAuthParams(BaseModel):
    code: str = Field(default=None)
    error: str = Field(default=None)
    state: str
