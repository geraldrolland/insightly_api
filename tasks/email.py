from insightly_api.celery_worker import celery
from insightly_api.core.settings import settings

@celery.task(
        name="send_verification_email",
        autortry_for=(Exception,),
        retry_kwargs={"max_retries": 3, "countdown": 5},
        )
def send_verification_email(email: str, body: dict):
    from insightly_api.utils import send_mail, log_to_file
    try:
        send_mail(email, "Verify your email", "email_verification.html", body=body)
        return "verification email sent successfully"
    except Exception as e:
        log_to_file(f"Failed to send verification email to {email}: {str(e)}")

@celery.task(
        name="send_welcome_email",
        autoretry_for=(Exception,),
        retry_kwargs={"max_retries": 3, "countdown": 5}
        )
def send_welcome_email(email: str):
    from insightly_api.utils import send_mail, log_to_file

    body = {
        "login_url": f"{settings.APP_HOST}?auth_state=login",
        "support_center_url": f"{settings.APP_HOST}/support-center"
    }
    try:
        send_mail(email, "Welcome To Insightly", "welcome_email.html", body)
        return "welcome email sent successfully"
    except Exception as e:
        log_to_file(f"Failed to send welcome email to {email}: {str(e)}")
        



@celery.task(name="send_otp_email")
def send_otp_email(email: str, body: dict[str, str] = None):
    from insightly_api.utils import send_mail, log_to_file
    try:
        send_mail(email, "Verify Your OTP", "otp_email.html", body)
    except Exception as e:
        log_to_file(f"Failed to send OTP email to {email}: {str(e)}")