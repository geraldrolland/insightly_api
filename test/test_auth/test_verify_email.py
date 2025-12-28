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
    return "api/v1/auth/verify-email"

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

def test_with_missing_token_and_next(client, api_url):
    response = client.get(api_url)
    assert response.status_code == 422
    
def test_with_invalid_token_and_next(client, api_url):
    response = client.get(api_url, params={"token": "invalidtoken", "next": "login"})
    assert response.status_code == 400
    
def test_with_valid_token_and_next(client, api_url, session):
    from insightly_api.utils import generate_verification_link

    user = User(
        email="testuser@example.com",
        hashed_password="SomeHashedPassword",
        agree_toTermsAndPolicy=True,
        is_active=True,
        is_email_verified=False,
        is_MFA_enabled=False
        )
    session.add(user)
    session.commit()
    token, next = tuple(generate_verification_link(user.email, next="nexturl").split("?")[1].split("&"))
    response = client.get(api_url, params={"token": token.split("=")[1], "next": next.split("=")[1]})
    assert response.status_code == 200
    user = session.exec(select(User).where(User.email == user.email)).one()
    assert user.is_email_verified