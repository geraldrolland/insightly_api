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
    return "api/v1/auth/verify-otp"

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


def test_with_empty_payload(client, api_url):
    response = client.post(api_url, json={})
    assert response.status_code == 422
    
def test_with_non_digit_otp_code(client, api_url):
    response = client.post(api_url, json={"otp_code": "abcdef"})
    assert response.status_code == 422
    
def test_with_incomplete_otp_code(client, api_url):
    response = client.post(api_url, json={"otp_code": "123"})
    assert response.status_code == 422
    
def test_with_extra_field_in_payload(client, api_url):
    response = client.post(api_url, json={"otp_code": "123456", "extra_field": "extra_value"})
    assert response.status_code == 422
    
def test_with_missing_otp_ctx_in_cookie(client, api_url):
    response = client.post(api_url, json={"otp_code": "123456"})
    assert response.status_code == 422
    
def test_with_invalid_otp_ctx_in_cookie(client, api_url):
    client.cookies.set("otp_ctx", "invalidtoken")
    response = client.post(api_url, json={"otp_code": "123456"})
    assert response.status_code == 401
    


def test_with_valid_otp_code_and_token(client, api_url, session):
    from insightly_api.main import redis_client
    from insightly_api.utils import generate_otp
    from insightly_api.utils import hash, sign_cookie
    import uuid
    import json

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=True
    )
    session.add(user)
    session.commit()
    otp_code = generate_otp(length=6)
    otp_token = str(uuid.uuid4())
    redis_client.set(name=otp_token, value=json.dumps({"otp_code_hash": hash(otp_code), "attempts": 0}), ex=2*60)
    payload = {
        "email": user.email,
        "otp_token": otp_token
    }
    value = sign_cookie(payload)
    client.cookies.set("otp_ctx", value)
    response = client.post(api_url, json={"otp_code": otp_code})
    assert response.status_code == 200
    assert response.cookies.get("auth_token") is not None

def test_otp_retry(client, api_url, session):
    from insightly_api.main import redis_client
    from insightly_api.utils import generate_otp
    from insightly_api.utils import hash, sign_cookie
    import uuid
    import json

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=True
    )
    session.add(user)
    session.commit()
    otp_code = generate_otp(length=6)
    otp_token = str(uuid.uuid4())
    redis_client.set(name=otp_token, value=json.dumps({"otp_code_hash": hash(otp_code), "attempts": 1}), ex=2*60)
    payload = {
        "email": user.email,
        "otp_token": otp_token
    }

    value = sign_cookie(payload)
    client.cookies.set("otp_ctx", value)
    response = client.post(api_url, json={"otp_code": "123456"})
    assert response.status_code == 400
    assert json.loads(redis_client.get(otp_token)).get("attempts") == 2

def test_exceed_maximum_retry(client, api_url, session):
    from insightly_api.main import redis_client
    from insightly_api.utils import generate_otp
    from insightly_api.utils import hash, sign_cookie
    import uuid
    import json

    user = User(
        email="testuser@example.com",
        hashed_password=hash("Testpassword123$"),
        agree_toTermsAndPolicy=True,
        is_email_verified=True,
        is_MFA_enabled=True
    )
    session.add(user)
    session.commit()
    otp_code = generate_otp(length=6)
    otp_token = str(uuid.uuid4())
    redis_client.set(name=otp_token, value=json.dumps({"otp_code_hash": hash(otp_code), "attempts": 3}), ex=2*60)
    payload = {
        "email": user.email,
        "otp_token": otp_token
    }

    value = sign_cookie(payload)
    client.cookies.set("otp_ctx", value)
    response = client.post(api_url, json={"otp_code": "123456"})
    assert response.status_code == 403
    assert redis_client.get(otp_token) is None