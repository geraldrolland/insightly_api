import pytest
from fastapi.testclient import TestClient
from insightly_api.core import settings
from insightly_api.dependencies import get_session, get_test_session
from insightly_api.models.user_model import User
from sqlmodel import select
from insightly_api.main import app

postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def api_url():
    return "api/v1/auth/register"

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
    
def test_invalid_field_values(client, api_url):
    payload = {
        "email": "invalidemail",
        "password": "short",
        "confirm_password": "mismatch",
        "agree_toTermsAndPolicy": "not bool"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422
    
def test_with_mismatched_passwords(client, api_url):
    payload = {
        "email": "testuser@example.com",
        "password": "Password123$",
        "confirm_password": "differentpassword",
        "agree_toTermsAndPolicy": True
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422

def test_agree_toTermsAndPolicy_false(client, api_url):
    payload = {
        "email": "testuser@example.com",
        "password": "Password123$",
        "confirm_password": "Password123$",
        "agree_toTermsAndPolicy": False
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 400
    
def test_with_valid_payload(client, api_url, session):
    payload = {
        "email": "testuser@example.com",
        "password": "Password123$",
        "confirm_password": "Password123$",
        "agree_toTermsAndPolicy": True
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 201
    user = session.exec(select(User).where(User.email == payload["email"])).first()
    assert user is not None