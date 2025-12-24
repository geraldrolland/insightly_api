from fastapi.testclient import TestClient
from unittest import TestCase
from insightly_api.dependencies import get_session
from insightly_api.models.user_model import User
from sqlmodel import select
import os
from dotenv import load_dotenv
from pathlib import Path
from insightly_api.db_config import get_engine,  SQLModel

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)
os.environ["ENVIRONMENT"] = "test"
engine = get_engine()





class TestRegisterEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app
        from sqlmodel import  Session
        

        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = Session(engine)
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
        self.session = Session(engine)
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
        from sqlmodel import  Session
        

        SQLModel.metadata.create_all(engine)
        self.client = TestClient(app)
        self.session = Session(engine)
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

    def tearDown(self):

        self.session.close()
        SQLModel.metadata.drop_all(engine)
        return super().tearDown()

class TestPasswordResetEndpoint(TestCase):
    pass

class TestOTPVerificationEndpoint(TestCase):
    pass

class TestEnableMFAEndpoint(TestCase):
    pass

class TestDisableMFAEndpoint(TestCase):
    pass

class TestEmailEndpoint(TestCase):
    pass

class TestLogoutEndpoint(TestCase):
    pass    

