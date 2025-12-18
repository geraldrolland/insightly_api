import os
from dotenv import load_dotenv
from insightly_api.celery_worker import celery

dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')

load_dotenv(dotenv_path)

print("THIS IS THE USERNAME ", os.getenv('MAIL_USERNAME'))

@celery.task(name="send_verification_email")
def send_verification_email(email: str, body: dict):
    pass

@celery.task(name="send_welcome_email")
def send_welcome_email(email: str):
    pass

@celery.task(name="send_otp_email")
def send_otp_email(email:str, body: dict):
    pass