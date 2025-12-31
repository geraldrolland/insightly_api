import pytest
from fastapi.testclient import TestClient
from insightly_api.core import settings
from insightly_api.dependencies import get_session, get_test_session
from insightly_api.models.user_model import User
from insightly_api.main import app

postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def api_url():
    return "api/v1/auth/login"

@pytest.fixture(scope="module")
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

def test_with_empty_payload(client, api_url):
    response = client.post(api_url, json={})
    assert response.status_code == 422
    
def test_with_missing_fields(client, api_url):
    payload = {
        "email": "testuser@example.com"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422

def test_with_invalid_credentials(client, api_url):
    payload = {
        "email": "testuser@example.com",
        "password": "WrongPassword123$"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 401
    
def test_with_valid_credentials(client, api_url, session):
    from insightly_api.utils import hash
        # First, create a user in the database
    user = User(
        email="testuser@example.com",
        hashed_password=hash("HashedPassword123$"),
        agree_toTermsAndPolicy=True,
        is_active=True,
        is_email_verified=True,
        is_MFA_enabled=False
    )
    session.add(user)
    session.commit()

    payload = {
        "email": "testuser@example.com",
        "password": "HashedPassword123$"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 200
    assert response.cookies.get("auth_token") is not None

def test_with_MFA_enabled_user(client, api_url, session):
    from insightly_api.utils import hash
        # First, create a user in the database
    user = User(
        email="testuser@example.com",
        hashed_password=hash("HashedPassword123$"),
        agree_toTermsAndPolicy=True,
        is_active=True,
        is_email_verified=True,
        is_MFA_enabled=True
        )
    session.add(user)
    session.commit()
    payload = {
        "email": user.email,
        "password": "HashedPassword123$"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 404