from celery import uuid
from fastapi.testclient import TestClient
from unittest import TestCase
from insightly_api.dependencies import get_session
from insightly_api.models.user_model import User
from sqlmodel import select
import os
from dotenv import load_dotenv
from pathlib import Path
from insightly_api.db_config import get_engine,  SQLModel
from insightly_api.dependencies import get_test_session, get_session
from insightly_api.main import app

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)
os.environ["ENVIRONMENT"] = "test"
engine = get_engine()
session = get_test_session()
app.dependency_overrides[get_session] = lambda: session


class TestRegisterEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app
        
        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = session
        self.select = select
        self.api_url = "/api/v1/auth/register"
        return super().setUp()
    
    def test_with_empty_payload(self):
        response = self.client.post(self.api_url, json={})
        self.assertEqual(response.status_code, 422)
    
    def test_with_missing_fields(self):
        payload = {
            "email": "testuser@example.com"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_invalid_field_values(self):
        payload = {
            "email": "invalidemail",
            "password": "short",
            "confirm_password": "mismatch",
            "agree_toTermsAndPolicy": "not bool"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_with_mismatched_passwords(self):
        payload = {
            "email": "testuser@example.com",
            "password": "Password123$",
            "confirm_password": "differentpassword",
            "agree_toTermsAndPolicy": True
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_agree_toTermsAndPolicy_false(self):
        payload = {
            "email": "testuser@example.com",
            "password": "Password123$",
            "confirm_password": "Password123$",
            "agree_toTermsAndPolicy": False
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 400)
    
    def test_with_valid_payload(self):
        payload = {
            "email": "testuser@example.com",
            "password": "Password123$",
            "confirm_password": "Password123$",
            "agree_toTermsAndPolicy": True
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 201)
        user = self.session.exec(self.select(User).where(User.email == payload["email"])).first()
        self.assertIsNotNone(user)
        

    def tearDown(self):
        self.session.close()
        SQLModel.metadata.drop_all(engine)
        return super().tearDown()


class TestLoginEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app
        from sqlmodel import  Session
        

        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = session
        self.select = select
        self.api_url = "/api/v1/auth/login"
        return super().setUp()
    
    def test_with_empty_payload(self):
        response = self.client.post(self.api_url, json={})
        self.assertEqual(response.status_code, 422)
    
    def test_with_missing_fields(self):
        payload = {
            "email": "testuser@example.com"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)

    def test_with_invalid_credentials(self):
        payload = {
            "email": "testuser@example.com",
            "password": "WrongPassword123$"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 401)
    
    def test_with_valid_credentials(self):
        from insightly_api.utils import hash_password
        # First, create a user in the database
        user = User(
            email="testuser@example.com",
            hashed_password=hash_password("HashedPassword123$"),
            agree_toTermsAndPolicy=True,
            is_active=True,
            is_email_verified=True,
            is_MFA_enabled=False
        )
        self.session.add(user)
        self.session.commit()

        payload = {
            "email": "testuser@example.com",
            "password": "HashedPassword123$"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.cookies.get("access_token"))

    def tearDown(self):
        self.session.close()
        SQLModel.metadata.drop_all(engine)
        return super().tearDown()

class TestVerifyEmailEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app


        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = session
        self.select = select
        self.api_url = "/api/v1/auth/verify-email"
        return super().setUp()
    
    def test_with_missing_token_and_next(self):
        response = self.client.get(self.api_url)
        self.assertEqual(response.status_code, 422)
    
    def test_with_invalid_token_and_next(self):
        response = self.client.get(self.api_url, params={"token": "invalidtoken", "next": "login"})
        self.assertEqual(response.status_code, 400)
    
    def test_with_valid_token_and_next(self):
        from insightly_api.utils import generate_verification_link

        user = User(
            email="testuser@example.com",
            hashed_password="SomeHashedPassword",
            agree_toTermsAndPolicy=True,
            is_active=True,
            is_email_verified=False,
            is_MFA_enabled=False
            )
        self.session.add(user)
        self.session.commit()
        token, next = tuple(generate_verification_link(user.email, next="nexturl").split("?")[1].split("&"))
        response = self.client.get(self.api_url, params={"token": token.split("=")[1], "next": next.split("=")[1]})
        self.assertEqual(response.status_code, 200)
        user = self.session.exec(self.select(User).where(User.email == user.email)).one()
        self.assertTrue(user.is_email_verified)

    def tearDown(self):
        self.session.close()
        SQLModel.metadata.drop_all(engine)
        return super().tearDown()

class TestPasswordResetEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app
        from sqlmodel import  Session
        

        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = session
        self.select = select
        self.api_url = "/api/v1/auth/reset-password"
        return super().setUp()
    
    def test_with_empty_payload(self):
        response = self.client.post(self.api_url, json={})
        self.assertEqual(response.status_code, 422)
    
    def test_with_incomplete_payload(self):
        payload = {
            "password": "testpassword"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_with_invalid_payload(self):
        payload = {
            "password": "testpassword",
            "confirm_password": "testpassword"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_with_extra_field(self):
        payload = {
            "password": "examplepassword",
            "confirm_password": "examplepassword",
            "extra_field": "extra_value"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_with_mismatch_passwords(self):
        payload = {
            "password": "Testpassword123$",
            "confirm_password": "mismatchpassword"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_with_valid_payload_without_allowtoken_in_cookie(self):
        payload = {
            "password": "Testpassword123$",
            "confirm_password": "Testpassword123$"
        }
        response = self.client.post(self.api_url, json=payload)
        self.assertEqual(response.status_code, 422)
    
    def test_with_valid_payload_withinvalid_allowtoken_in_cookie(self):
        payload = {
            "password": "Testpassword123$",
            "confirm_password": "Testpassword123$"
        }
        response = self.client.post(self.api_url, json=payload, cookies={"allow_pswd_reset_token": "invalid_password_reset_token"})
        self.assertEqual(response.status_code, 401)
    
    def test_with_valid_payload_with_validallowtoken_in_cookie(self):
        from insightly_api.main import redis_client
        from insightly_api.utils import hash_password, sign_cookie, verify_password
        import uuid

        user = User(
            email="testuser@example.com",
            hashed_password=hash_password("Testpassword123$"),
            agree_toTermsAndPolicy=True,
            is_email_verified=True,
            is_MFA_enabled=False
        )
        self.session.add(user)
        self.session.commit()
        allow_pswd_reset_token = str(uuid.uuid4())
        redis_client.set(name=allow_pswd_reset_token, value=user.email, ex=7*60)
        payload = {
            "password": "Newtestpassword123$",
            "confirm_password": "Newtestpassword123$"
        }
        response = self.client.post(self.api_url, json=payload, cookies={"allow_pswd_reset_token": sign_cookie(allow_pswd_reset_token)})
        self.assertEqual(response.status_code, 200)
        email = redis_client.get(allow_pswd_reset_token)
        self.assertIsNone(email)
        user = self.session.exec(self.select(User).where(User.email == "testuser@example.com")).one()
        self.assertTrue(verify_password(payload.get("password"), user.hashed_password))

    def tearDown(self):
        self.session.close()
        SQLModel.metadata.drop_all(engine)
        return super().tearDown()

class TestOTPVerificationEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app
        from sqlmodel import  Session
        

        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = session
        self.select = select
        self.api_url = "/api/v1/auth/verify-otp"
        return super().setUp()

    def test_with_empty_payload(self):
        response = self.client.post(self.api_url, json={})
        self.assertEqual(response.status_code, 422)
    
    def test_with_non_digit_otp_code(self):
        response = self.client.post(self.api_url, json={"otp_code": "abcdef"})
        self.assertEqual(response.status_code, 422)
    
    def test_with_incomplete_otp_code(self):
        response = self.client.post(self.api_url, json={"otp_code": "123"})
        self.assertEqual(response.status_code, 422)
    
    def test_with_extra_field_in_payload(self):
        response = self.client.post(self.api_url, json={"otp_code": "123456", "extra_field": "extra_value"})
        self.assertEqual(response.status_code, 422)
    
    def test_with_missing_otp_token_cookie(self):
        response = self.client.post(self.api_url, json={"otp_code": "123456"})
        self.assertEqual(response.status_code, 422)
    
    def test_with_invalid_otp_token_cookie(self):
        response = self.client.post(self.api_url, json={"otp_code": "123456"}, cookies={"otp_token": "invalidtoken"})
        print(response.json())
        self.assertEqual(response.status_code, 401)
    
    def test_with_valid_otp_code_and_token(self):
        from insightly_api.main import redis_client
        from insightly_api.utils import generate_otp
        from insightly_api.utils import hash_password
        import uuid

        user = User(
            email="testuser@example.com",
            hashed_password=hash_password("Testpassword123$"),
            agree_toTermsAndPolicy=True,
            is_email_verified=True,
            is_MFA_enabled=True
        )
        self.session.add(user)
        self.session.commit()
        otp_code = generate_otp(length=6)
        otp_token = str(uuid.uuid4())
        redis_client.set(name=otp_token, value=otp_code, ex=2*60)
        payload = {
            "otp_code": otp_code
        }
        response = self.client.post(self.api_url, json=payload, cookies={"otp_token": otp_token})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.cookies.get("access_token"))

    def tearDown(self):
        self.session.close()
        SQLModel.metadata.drop_all(engine)
        return super().tearDown()

class TestEnableMFAEndpoint(TestCase):
    pass

class TestDisableMFAEndpoint(TestCase):
    pass

class TestEmailEndpoint(TestCase):
    pass

class TestLogoutEndpoint(TestCase):
    pass    

