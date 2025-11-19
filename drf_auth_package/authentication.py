"""Custom authentication classes for DRF."""

import logging
from typing import Optional, Tuple

from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest
from rest_framework import authentication, exceptions

from drf_auth_package.models import User
from drf_auth_package.services.jwt_service import JWTService

logger = logging.getLogger(__name__)


class JWTAuthentication(authentication.BaseAuthentication):
    """
    JWT authentication for DRF.

    Clients should authenticate by passing the token in the Authorization header.
    Example: Authorization: Bearer <token>
    """

    keyword = "Bearer"

    def authenticate(self, request: HttpRequest) -> Optional[Tuple[User, str]]:
        """
        Authenticate the request and return a two-tuple of (user, token).

        Args:
            request: The HTTP request object.

        Returns:
            Tuple of (user, token) if authentication successful, None otherwise.

        Raises:
            AuthenticationFailed: If authentication fails.
        """
        auth_header = authentication.get_authorization_header(request).decode("utf-8")

        if not auth_header:
            return None

        parts = auth_header.split()

        if len(parts) == 0:
            return None

        if parts[0].lower() != self.keyword.lower():
            return None

        if len(parts) == 1:
            raise exceptions.AuthenticationFailed("Invalid token header. No credentials provided.")
        elif len(parts) > 2:
            raise exceptions.AuthenticationFailed(
                "Invalid token header. Token string should not contain spaces."
            )

        token = parts[1]

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token: str) -> Tuple[User, str]:
        """
        Authenticate the credentials and return the user.

        Args:
            token: JWT token.

        Returns:
            Tuple of (user, token).

        Raises:
            AuthenticationFailed: If authentication fails.
        """
        user = JWTService.get_user_from_token(token)

        if user is None:
            raise exceptions.AuthenticationFailed("Invalid or expired token.")

        if not user.is_active:
            raise exceptions.AuthenticationFailed("User account is disabled.")

        return (user, token)

    def authenticate_header(self, request: HttpRequest) -> str:
        """
        Return a string to be used as the value of the WWW-Authenticate header.

        Args:
            request: The HTTP request object.

        Returns:
            Authentication header value.
        """
        return self.keyword


class EmailBackend(ModelBackend):
    """
    Custom authentication backend that uses email instead of username.
    """

    def authenticate(
        self,
        request: Optional[HttpRequest],
        username: Optional[str] = None,
        password: Optional[str] = None,
        **kwargs
    ) -> Optional[User]:
        """
        Authenticate using email and password.

        Args:
            request: The HTTP request object.
            username: Email address (named username for compatibility).
            password: User's password.

        Returns:
            User object if authentication successful, None otherwise.
        """
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            # Run the default password hasher to reduce the timing difference
            User().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            logger.info(f"User {username} authenticated successfully")
            return user

        logger.warning(f"Failed authentication attempt for email: {username}")
        return None

    def get_user(self, user_id: str) -> Optional[User]:
        """
        Get a user by ID.

        Args:
            user_id: User's ID.

        Returns:
            User object if found, None otherwise.
        """
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

        return user if self.user_can_authenticate(user) else None
