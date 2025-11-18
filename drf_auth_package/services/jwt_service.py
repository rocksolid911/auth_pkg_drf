"""JWT authentication service."""

import logging
from datetime import timedelta
from typing import Dict, Optional, Tuple

import jwt
from django.utils import timezone

from drf_auth_package import conf
from drf_auth_package.models import RefreshToken, User

logger = logging.getLogger(__name__)


class JWTService:
    """Service for JWT token generation and validation."""

    @staticmethod
    def generate_access_token(user: User) -> str:
        """
        Generate an access token for a user.

        Args:
            user: The user to generate the token for.

        Returns:
            JWT access token as a string.
        """
        payload = {
            "user_id": str(user.id),
            "email": user.email,
            "exp": timezone.now() + timedelta(minutes=conf.JWT_ACCESS_TOKEN_LIFETIME_MINUTES),
            "iat": timezone.now(),
            "type": "access",
        }

        token = jwt.encode(
            payload,
            conf.JWT_SIGNING_KEY,
            algorithm=conf.JWT_ALGORITHM
        )

        logger.info(f"Generated access token for user {user.email}")
        return token

    @staticmethod
    def generate_refresh_token(
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """
        Generate a refresh token for a user and store it in the database.

        Args:
            user: The user to generate the token for.
            ip_address: IP address of the request.
            user_agent: User agent string of the request.

        Returns:
            JWT refresh token as a string.
        """
        payload = {
            "user_id": str(user.id),
            "exp": timezone.now() + timedelta(days=conf.JWT_REFRESH_TOKEN_LIFETIME_DAYS),
            "iat": timezone.now(),
            "type": "refresh",
        }

        token = jwt.encode(
            payload,
            conf.JWT_SIGNING_KEY,
            algorithm=conf.JWT_ALGORITHM
        )

        # Store the refresh token in the database
        expires_at = timezone.now() + timedelta(days=conf.JWT_REFRESH_TOKEN_LIFETIME_DAYS)
        RefreshToken.objects.create(
            user=user,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info(f"Generated refresh token for user {user.email}")
        return token

    @staticmethod
    def generate_token_pair(
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate both access and refresh tokens for a user.

        Args:
            user: The user to generate tokens for.
            ip_address: IP address of the request.
            user_agent: User agent string of the request.

        Returns:
            Dictionary containing access and refresh tokens.
        """
        access_token = JWTService.generate_access_token(user)
        refresh_token = JWTService.generate_refresh_token(user, ip_address, user_agent)

        return {
            "access": access_token,
            "refresh": refresh_token,
        }

    @staticmethod
    def verify_token(token: str, token_type: str = "access") -> Dict:
        """
        Verify and decode a JWT token.

        Args:
            token: The JWT token to verify.
            token_type: Expected token type ("access" or "refresh").

        Returns:
            Decoded token payload.

        Raises:
            jwt.ExpiredSignatureError: If token has expired.
            jwt.InvalidTokenError: If token is invalid.
        """
        try:
            payload = jwt.decode(
                token,
                conf.JWT_SIGNING_KEY,
                algorithms=[conf.JWT_ALGORITHM]
            )

            if payload.get("type") != token_type:
                raise jwt.InvalidTokenError(f"Invalid token type. Expected {token_type}.")

            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Tuple[str, User]:
        """
        Generate a new access token from a refresh token.

        Args:
            refresh_token: The refresh token.

        Returns:
            Tuple of (new_access_token, user).

        Raises:
            jwt.InvalidTokenError: If refresh token is invalid or revoked.
        """
        # Verify the refresh token
        payload = JWTService.verify_token(refresh_token, token_type="refresh")

        # Check if the refresh token exists and is valid in the database
        try:
            stored_token = RefreshToken.objects.get(token=refresh_token)
        except RefreshToken.DoesNotExist:
            logger.warning("Refresh token not found in database")
            raise jwt.InvalidTokenError("Invalid refresh token")

        if not stored_token.is_valid():
            logger.warning(f"Refresh token is not valid (revoked or expired)")
            raise jwt.InvalidTokenError("Refresh token is not valid")

        # Get the user
        try:
            user = User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            logger.warning(f"User not found for token: {payload['user_id']}")
            raise jwt.InvalidTokenError("User not found")

        # Generate a new access token
        new_access_token = JWTService.generate_access_token(user)

        logger.info(f"Refreshed access token for user {user.email}")
        return new_access_token, user

    @staticmethod
    def revoke_refresh_token(refresh_token: str) -> None:
        """
        Revoke a refresh token.

        Args:
            refresh_token: The refresh token to revoke.
        """
        try:
            stored_token = RefreshToken.objects.get(token=refresh_token)
            stored_token.revoked = True
            stored_token.save()
            logger.info(f"Revoked refresh token for user {stored_token.user.email}")
        except RefreshToken.DoesNotExist:
            logger.warning("Attempted to revoke non-existent refresh token")

    @staticmethod
    def revoke_all_user_tokens(user: User) -> None:
        """
        Revoke all refresh tokens for a user.

        Args:
            user: The user whose tokens to revoke.
        """
        count = RefreshToken.objects.filter(user=user, revoked=False).update(revoked=True)
        logger.info(f"Revoked {count} refresh tokens for user {user.email}")

    @staticmethod
    def get_user_from_token(token: str) -> Optional[User]:
        """
        Get a user from an access token.

        Args:
            token: The access token.

        Returns:
            User object if token is valid, None otherwise.
        """
        try:
            payload = JWTService.verify_token(token, token_type="access")
            user = User.objects.get(id=payload["user_id"])
            return user
        except (jwt.InvalidTokenError, User.DoesNotExist):
            return None
