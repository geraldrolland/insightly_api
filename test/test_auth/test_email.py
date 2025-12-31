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
    return "api/v1/auth/email"

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

def test_with_incorrect_payload(client, api_url):
    response = client.post(api_url, json={"incorrect_field": "incorrect_value"})

def test_with_invalid_email(client, api_url):
    payload = {
        "email": "testuser@123"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422

def test_with_extra_field_in_payload(client, api_url):
    payload = {
        "email": "testuser@example.com",
        "extra_field": "extra_value"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422

def test_with_email_that_donot_exist(client, api_url):
    response = client.post(api_url, json={"email": "testuser@example.com"})
    assert response.status_code == 404

def test_with_email_that_exist(client, api_url, session):
    user = User(
        email="testuser@gmail.com",
        hashed_password=hash("Testpassword123$"),
        is_email_verified=True,
        is_active=True,
        is_MFA_enabled=False,
        agree_toTermsAndPolicy=True
    )
    session.add(user)
    session.commit()
    
    response = client.post(api_url, json={"email": user.email})
    assert response.status_code == 200