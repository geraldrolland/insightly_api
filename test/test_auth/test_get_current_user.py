from unittest.mock import patch
import jwt
import pytest
from fastapi.testclient import TestClient
from insightly_api.core.settings import settings
from insightly_api.dependencies import get_session
from insightly_api.models.user_model import User
from insightly_api.main import app

postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def api_url():
    return "api/v1/auth/me"

@pytest.fixture(autouse=True)
def test_engine():
    from sqlmodel import SQLModel, create_engine

    engine = create_engine(postgresql_test_url, future=True)
    SQLModel.metadata.create_all(engine)
    yield engine
    SQLModel.metadata.drop_all(engine)

@pytest.fixture()
def session(test_engine):
    from sqlmodel import  Session
    
    session = Session(test_engine)
    yield session
    session.close()

@pytest.fixture(autouse=True)
def override_dependency(session):
    app.dependency_overrides[get_session] = lambda: session

def test_without_auth_token_cookie(client, api_url):
    response = client.get(api_url)
    assert response.status_code == 401
    
def test_with_invalid_auth_token_cookie(client, api_url):
    client.cookies.set("auth_token", "invalidtoken")
    response = client.get(api_url)
    assert response.status_code == 401
    
def test_with_valid_auth_token_cookie(client, api_url, session):
    from insightly_api.utils import hash, sign_cookie, generate_access_token

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=True
    )
    session.add(user)
    session.commit()
    access_token, refresh_token = generate_access_token({"email": user.email})
    value = sign_cookie({"access_token": access_token, "refresh_token": refresh_token})
    client.cookies.set("auth_token", value)
    response = client.get(api_url)
    assert response.cookies.get("auth_token") is not None
    assert response.status_code == 200
    
def test_with_expired_access_token_in_auth_token_cookie(client, api_url, session):
    from insightly_api.utils import hash, sign_cookie, generate_access_token, verify_signed_cookie
    import jwt
    from unittest.mock import patch

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=True
    )
    session.add(user)
    session.commit()
    access_token, refresh_token = generate_access_token({"email": user.email})

    value = sign_cookie({"access_token": access_token, "refresh_token": refresh_token})
        
        # helper to simulate first call raising, second call succeeds
    def fake_verify_access_token(token):

        if token == access_token:
            raise jwt.ExpiredSignatureError
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        
    with patch("insightly_api.dependencies.verify_access_token", side_effect=fake_verify_access_token):
        client.cookies.set("auth_token", value)
        response = client.get(api_url)
    assert response.status_code == 200
    new_access_token = verify_signed_cookie(response.cookies.get("auth_token")).get("access_token")
    assert access_token != new_access_token
    
def test_with_expired_refresh_token_in_auth_token_cookie(client, api_url, session):
    from insightly_api.utils import hash, sign_cookie, generate_access_token
    from insightly_api.exceptions import ExpiredRefreshTokenError

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=True
        )
    session.add(user)
    session.commit()
    access_token, refresh_token = generate_access_token({"email": user.email})
    value = sign_cookie({"access_token": access_token, "refresh_token": refresh_token})
    with patch("insightly_api.dependencies.verify_access_token", side_effect=jwt.ExpiredSignatureError):
        with patch("insightly_api.dependencies.refresh_access_token", side_effect=ExpiredRefreshTokenError):
            client.cookies.set("auth_token", value)
            response = client.get(api_url)
    assert response.status_code == 401

    
