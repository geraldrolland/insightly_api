from fastapi.testclient import TestClient
from unittest import TestCase
from insightly_api.dependencies import get_session
from insightly_api.models.user_model import User
from sqlmodel import select
import os



class TestRegisterEndpoint(TestCase):
    def setUp(self):
        from insightly_api.main import app

        print("Setting up TestClient and test database session...")
        self.client = TestClient(app)
        self.session = get_session()
        self.select = select
        self.model = User
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
        self.assertEqual(response.status_code, 400)

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
        user = self.session.exec(self.select(self.model).where(self.model.email == payload["email"])).first()
        self.assertIsNotNone(user)

    @classmethod
    def setUpClass(cls):
        from dotenv import load_dotenv
        from pathlib import Path

        env_path = Path(__file__).resolve().parent.parent / ".env"
        load_dotenv(env_path)
        
        print("Setting ENVIRONMENT to 'test' for test database")
        os.environ["ENVIRONMENT"] = "test"
        print("This is the current ENVIRONMENT: ", os.getenv("ENVIRONMENT"))
    
    def tearDown(self):
        from insightly_api.db_config import engine, SQLModel

        print("Tearing down test database...")
        SQLModel.metadata.drop_all(engine)
        self.session.close()
        return super().tearDown()


class TestLoginEndpoint(TestCase):
    pass

class TestVerifyEmailEndpoint(TestCase):
    pass

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

