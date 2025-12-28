from sqlmodel import select
from typing import Any
from insightly_api.core.settings import settings
import requests
from insightly_api.models.user_model import User

def google_get_access_token(code: str, redirect_uri: str) -> str:
    data = {
        'code': code,
        'client_id': settings.CLIENT_ID,
        'client_secret': settings.CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    response = requests.post(settings.GOOGLE_ACCESS_TOKEN_OBTAIN_URL, data=data)
    if not response.ok:
        error_details = response.json().get('error_description', 'Unknown error')
        raise ValueError(f'Could not get access token from Google: {error_details}')
    response_data = response.json()
    if 'access_token' not in response_data:
        raise ValueError('Access token not found in Google response')
    access_token = response_data['access_token']
    return access_token

# Get user info from google
def google_get_user_info(access_token: str) -> dict[str, Any]:
    response = requests.get(
        settings.GOOGLE_USER_INFO_URL,
        headers={'Authorization': f'Bearer {access_token}'}
    )

    if not response.ok:
        raise ValueError('Could not get user info from Google.')
    return response.json()

def login_with_google(code, session):
    domain = settings.API_HOST
    redirect_uri = f'{domain}/api/google-auth'
    
    access_token = google_get_access_token(code=code, redirect_uri=redirect_uri)
    user_data = google_get_user_info(access_token=access_token)

    # Creates user in DB if first time login
    user = session.exec(select(User).where(User.email == user_data['email'])).one_or_none()
    if not user:
        user = User(
            email=user_data['email'],
            hashed_password=None,
            is_active=True,
            is_email_verified=True,
            is_MFA_enabled=False,
            agree_toTermsAndPolicy=True
        )
        session.add(user)
        session.commit()
    return user
