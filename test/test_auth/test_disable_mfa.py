from unittest.mock import patch
import jwt
import pytest
from fastapi.testclient import TestClient
from insightly_api.core import settings
from insightly_api.dependencies import get_session
from insightly_api.models.user_model import User
from insightly_api.main import app

postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def api_url():
    return "api/v1/auth/disable-mfa"

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
def user(client, session):
    from insightly_api.utils import hash, sign_cookie, generate_access_token

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=False,
    )
    session.add(user)
    session.commit()
    access_token, refresh_token = generate_access_token({"id": user.id, "email": user.email})
    auth_token = sign_cookie({"access_token": access_token, "refresh_token": refresh_token})
    client.cookies.set(name="auth_token", value=auth_token)
    return user

@pytest.fixture(autouse=True)
def override_dependency(session):
    app.dependency_overrides[get_session] = lambda: session

def test_without_auth_token_cookie(client, api_url):
    client.cookies.delete("auth_token")
    response = client.delete(api_url)
    assert response.status_code == 401

def test_with_invalid_auth_token_cookie(client, api_url):
    client.cookies.set("auth_token", "invalidtoken")
    response = client.delete(api_url)
    assert response.status_code == 401

def test_disable_mfa_when_mfa_not_enabled(client, api_url):
    response = client.delete(api_url)
    assert response.status_code == 400

def test_disable_mfa_successfully(client, api_url, session, user):
    user.is_MFA_enabled = True
    session.add(user)
    session.commit()
    response = client.delete(api_url)
    assert response.status_code == 200
    session.refresh(user)
    assert user.is_MFA_enabled is False