"""Tests for authentication flows."""

import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from drf_auth_package.models import User


class RegistrationTests(TestCase):
    """Tests for user registration."""

    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse("drf_auth_package:register")

    def test_register_user_success(self):
        """Test successful user registration."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123",
            "password_confirm": "TestPass123",
            "first_name": "Test",
            "last_name": "User",
        }

        response = self.client.post(self.register_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("user", response.data)
        self.assertIn("tokens", response.data)
        self.assertEqual(response.data["user"]["email"], "test@example.com")

        # Verify user was created in database
        self.assertTrue(User.objects.filter(email="test@example.com").exists())

    def test_register_duplicate_email(self):
        """Test registration with duplicate email."""
        # Create initial user
        User.objects.create_user(email="test@example.com", password="TestPass123")

        # Try to register with same email
        data = {
            "email": "test@example.com",
            "password": "NewPass123",
            "password_confirm": "NewPass123",
        }

        response = self.client.post(self.register_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_register_password_mismatch(self):
        """Test registration with mismatched passwords."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123",
            "password_confirm": "DifferentPass123",
        }

        response = self.client.post(self.register_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LoginTests(TestCase):
    """Tests for user login."""

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse("drf_auth_package:login")
        self.user = User.objects.create_user(
            email="test@example.com",
            password="TestPass123",
            first_name="Test",
            last_name="User"
        )

    def test_login_success(self):
        """Test successful login."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123",
        }

        response = self.client.post(self.login_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)
        self.assertIn("tokens", response.data)
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        data = {
            "email": "test@example.com",
            "password": "WrongPassword",
        }

        response = self.client.post(self.login_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_nonexistent_user(self):
        """Test login with non-existent user."""
        data = {
            "email": "nonexistent@example.com",
            "password": "TestPass123",
        }

        response = self.client.post(self.login_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class MeEndpointTests(TestCase):
    """Tests for the 'me' endpoint."""

    def setUp(self):
        self.client = APIClient()
        self.me_url = reverse("drf_auth_package:me")
        self.user = User.objects.create_user(
            email="test@example.com",
            password="TestPass123",
            first_name="Test",
            last_name="User"
        )

    def test_me_authenticated(self):
        """Test accessing me endpoint when authenticated."""
        # Login to get token
        login_url = reverse("drf_auth_package:login")
        login_data = {
            "email": "test@example.com",
            "password": "TestPass123",
        }
        login_response = self.client.post(login_url, login_data, format="json")
        access_token = login_response.data["tokens"]["access"]

        # Access me endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        response = self.client.get(self.me_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["email"], "test@example.com")

    def test_me_unauthenticated(self):
        """Test accessing me endpoint without authentication."""
        response = self.client.get(self.me_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PasswordChangeTests(TestCase):
    """Tests for password change."""

    def setUp(self):
        self.client = APIClient()
        self.password_change_url = reverse("drf_auth_package:password-change")
        self.user = User.objects.create_user(
            email="test@example.com",
            password="OldPass123"
        )

        # Get authentication token
        login_url = reverse("drf_auth_package:login")
        login_data = {
            "email": "test@example.com",
            "password": "OldPass123",
        }
        login_response = self.client.post(login_url, login_data, format="json")
        self.access_token = login_response.data["tokens"]["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

    def test_password_change_success(self):
        """Test successful password change."""
        data = {
            "old_password": "OldPass123",
            "new_password": "NewPass456",
            "new_password_confirm": "NewPass456",
        }

        response = self.client.post(self.password_change_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify new password works
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass456"))

    def test_password_change_wrong_old_password(self):
        """Test password change with wrong old password."""
        data = {
            "old_password": "WrongOldPass",
            "new_password": "NewPass456",
            "new_password_confirm": "NewPass456",
        }

        response = self.client.post(self.password_change_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class JWTTokenTests(TestCase):
    """Tests for JWT token management."""

    def setUp(self):
        self.client = APIClient()
        self.token_url = reverse("drf_auth_package:token-obtain")
        self.refresh_url = reverse("drf_auth_package:token-refresh")
        self.verify_url = reverse("drf_auth_package:token-verify")
        self.user = User.objects.create_user(
            email="test@example.com",
            password="TestPass123"
        )

    def test_obtain_token_pair(self):
        """Test obtaining token pair."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123",
        }

        response = self.client.post(self.token_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_refresh_token(self):
        """Test refreshing access token."""
        # Obtain initial tokens
        data = {
            "email": "test@example.com",
            "password": "TestPass123",
        }
        token_response = self.client.post(self.token_url, data, format="json")
        refresh_token = token_response.data["refresh"]

        # Refresh access token
        refresh_data = {"refresh": refresh_token}
        response = self.client.post(self.refresh_url, refresh_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_verify_valid_token(self):
        """Test verifying a valid token."""
        # Obtain token
        data = {
            "email": "test@example.com",
            "password": "TestPass123",
        }
        token_response = self.client.post(self.token_url, data, format="json")
        access_token = token_response.data["access"]

        # Verify token
        verify_data = {"token": access_token}
        response = self.client.post(self.verify_url, verify_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["valid"])

    def test_verify_invalid_token(self):
        """Test verifying an invalid token."""
        verify_data = {"token": "invalid-token"}
        response = self.client.post(self.verify_url, verify_data, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data["valid"])
