import pytest
from fastapi.testclient import TestClient
from insightly_api.core import settings
from insightly_api.dependencies import get_session, get_test_session
from insightly_api.models.user_model import User
from sqlmodel import select
settings.ENVIRONMENT = "test"
from insightly_api.main import app

postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def api_url():
    return "api/v1/auth/reset-password"

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
    
def test_with_incomplete_payload(client, api_url):
    payload = {
    "password": "testpassword"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422
    
def test_with_invalid_payload(client, api_url):
    payload = {
        "password": "testpassword",
        "confirm_password": "testpassword"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422
    
def test_with_extra_field(client, api_url):
    payload = {
        "password": "examplepassword",
        "confirm_password": "examplepassword",
        "extra_field": "extra_value"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422
    
def test_with_mismatch_passwords(client, api_url):
    payload = {
        "password": "Testpassword123$",
        "confirm_password": "mismatchpassword"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422
    
def test_with_valid_payload_without_allowtoken_in_cookie(client, api_url):
    payload = {
        "password": "Testpassword123$",
        "confirm_password": "Testpassword123$"
    }
    response = client.post(api_url, json=payload)
    assert response.status_code == 422
    
def test_with_valid_payload_withinvalid_allowtoken_in_cookie(client, api_url):
    payload = {
        "password": "Testpassword123$",
        "confirm_password": "Testpassword123$"
    }
    client.cookies.set("allow_pswd_reset_token", "invalidtoken")
    response = client.post(api_url, json=payload)
    assert response.status_code, 401
    
def test_with_valid_payload_with_validallowtoken_in_cookie(client, api_url, session):
    from insightly_api.main import redis_client
    from insightly_api.utils import hash, sign_cookie, verify_hash
    import uuid
    from unittest.mock import patch


    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=False
    )
    session.add(user)
    session.commit()
    allow_pswd_reset_token = str(uuid.uuid4())
    redis_client.set(name=allow_pswd_reset_token, value=user.email, ex=7*60)
    payload = {
        "password": "Newtestpassword123$",
        "confirm_password": "Newtestpassword123$"
    }
    client.cookies.set("allow_pswd_reset_token", sign_cookie(allow_pswd_reset_token))
    response = client.post(api_url, json=payload)
    assert response.status_code == 200
    email = redis_client.get(allow_pswd_reset_token)
    assert email is None
    user = session.exec(select(User).where(User.email == "testuser@example.com")).one()
    assert verify_hash(payload.get("password"), user.hashed_password) == True