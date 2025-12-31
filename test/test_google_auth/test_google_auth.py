import pytest
from fastapi.testclient import TestClient
from insightly_api.dependencies import get_session
from insightly_api.models.user_model import User
from insightly_api.main import app
from unittest.mock import patch

postgresql_test_url = "postgresql+psycopg2://testuser:testpassword@localhost/test_db"

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def api_url():
    return "api/v1/google-auth"

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

def test_with_empty_params(client, api_url):
    response = client.get(api_url, params={})
    assert response.status_code == 422

def test_with_incorrect_params(client, api_url):
    params = {
        "fake_param": "fake_value"
    }
    response = client.get(api_url, params=params)
    assert response.status_code == 422

def test_code_without_state_param_present(client, api_url):
    params = {
        "code": "testcode"
    }
    response = client.get(api_url, params=params)
    assert response.status_code == 422

def test_with_error_without_state_param_present(client, api_url):
    params = {
        "error": "validerror"
    }
    response =  client.get(api_url, params=params)
    assert response.status_code == 422

def test_with_only_state_param_present(client, api_url):
    params = {
        "state": "/login"
    }
    response = client.get(api_url, params=params)
    assert response.status_code == 404

def test_with_valid_params_without_user_agent(client, api_url):
    params = {
        "code": "validcode",
        "state": "/valid-state"
    }
    response = client.get(api_url, params=params)
    assert response.status_code == 404

def test_with_valid_payload_with_user_agent(client, api_url, session):
    params = {
        "code": "validcode",
        "state": "/validstate"
    }
    client.headers.update({"User-Agent": "test-agent"})

    user = User(
        email="testuser@example.com",
        hashed_password="",
        agree_toTermsAndPolicy=True,
        is_active=True,
        is_MFA_enabled=False,
        is_email_verified=True
    )
    session.add(user)
    session.commit()
    with patch("insightly_api.utils.normalize_user_agent", side_effect=lambda user_agent: user_agent), patch("insightly_api.routers.google_auth.login_with_google", side_effect=lambda code, session: user):
        response = client.get(api_url, params=params)
        assert response.status_code == 404    