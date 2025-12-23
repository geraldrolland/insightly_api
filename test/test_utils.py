from unittest import TestCase
from insightly_api.utils import *

class TestUtils(TestCase):
    def test_hash_and_verify_password(self):
        password = "StrongPassword123!"
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))

    def test_generate_and_verify_access_token(self):
        data = {"email": "test@example.com"}
        token = generate_access_token(data)
        payload = verify_access_token(token)
        self.assertEqual(payload["email"], data["email"])
    
    def test_refresh_access_token(self):
        data = {"email": "test@example.com"}
        token = generate_access_token(data)
        new_token = refresh_access_token(token)
        new_payload = verify_access_token(new_token)
        self.assertEqual(new_payload["email"], data["email"])
    
    def test_generate_verification_link(self):
        email = "test@example.com"
        next = "login"
        verification_link = generate_verification_link(email, next)
        self.assertIn("token=", verification_link)
        self.assertIn("next=login", verification_link)\
    
    def test_generate_otp(self):
        otp = generate_otp(length=6)
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())
    
    def test_send_mail(self):
        from pathlib import Path
        import os

        body = {"name": "Tester"}
        email = "test@example.com"
        with open(Path(__file__).resolve().parent.parent / "templates" / "test_email.html", "w") as f:
            f.write("<html><body><h1>hello {{name}}</h1></body></html>")
        try:
            send_mail(email, "Test Subject", "test_email.html", body)
        except Exception as e:
            self.fail(f"send_mail raised an exception: {str(e)}")
        os.remove(Path(__file__).resolve().parent.parent / "templates" / "test_email.html")
    
    def test_log_to_file(self):
        from datetime import datetime
        import os

        log_to_file("This is a test log message.")
        with open("error.log", "r") as f:
            logs = f.read()
        date, message = tuple(logs.strip().split(" - "))
        self.assertTrue(datetime.fromisoformat(date))
        self.assertIn("This is a test log message.", message)
        os.remove("error.log")
    
    def test_sign_and_verify_cookie(self):
        value = "test_cookie_value"
        signed_value = sign_cookie(value)
        verified_value = verify_signed_cookie(signed_value)
        self.assertEqual(value, verified_value)
    

    
