from fastapi import FastAPI, Form, UploadFile, File, Body, status
from type import UserRegistrationType, UserLoginType, PasswordChangeType, validate_otp, validate_registration
from typing import Annotated
from pydantic import AfterValidator
from fastapi.exceptions import HTTPException

app = FastAPI()

@app.post("/api/v1/user/register",  status_code=status.HTTP_201_CREATED, description="allow user to register by providing email, password and confirm password for registraton")
async def register_user(data: Annotated[UserRegistrationType, AfterValidator(validate_registration)]):
    if data.agree_toTermsAndPolicy != True:
        raise HTTPException(status_code=400, detail={"error": "terms and policy must be agreed to before proceeding with registration"})
    return {"detail": "user registered successfully"}

@app.post("/api/v1/user/login", status_code=status.HTTP_200_OK, description="allow user to log in by providing email and password as authentication credential")
async def login_user(data: UserLoginType):
    return {"detail": "logged in successfully"}

@app.post("/api/v1/user/password-change", status_code=status.HTTP_200_OK, description="allow user to provide password and confirm password for password change")
async def password_change(data: Annotated[PasswordChangeType, AfterValidator(validate_registration)]):
    return {"detail": "password changed succesfully"}

@app.post("/api/v1/user/email", status_code=status.HTTP_200_OK, description="allow user to provide email for password change")
async def user_email(email: Annotated[str, Body(embed=True, pattern=r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$'),]):
    return {"detail": "verification link has been set to the email successfully"}

@app.post("/api/v1/user/otp-verification", status_code=status.HTTP_200_OK, description="verifies provided otp from the user")
async def otp_verification(otp: Annotated[str, Body(embed=True), AfterValidator(validate_otp)]):
    return {"detail": "otp verified successfully"}
