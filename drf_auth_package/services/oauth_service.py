"""OAuth service for social authentication."""

import logging
from typing import Dict, Optional, Tuple

import requests
from django.core.exceptions import ValidationError

from drf_auth_package import conf
from drf_auth_package.models import User

logger = logging.getLogger(__name__)


class OAuthService:
    """Service for OAuth-based social authentication."""

    @staticmethod
    def verify_google_token(token: str) -> Optional[Dict]:
        """
        Verify a Google OAuth token and return user info.

        Args:
            token: Google OAuth token (ID token or access token).

        Returns:
            Dictionary with user info if valid, None otherwise.
        """
        try:
            # Verify token with Google
            response = requests.get(
                "https://www.googleapis.com/oauth2/v3/tokeninfo",
                params={"id_token": token},
                timeout=10
            )

            if response.status_code != 200:
                logger.warning(f"Google token verification failed: {response.text}")
                return None

            token_info = response.json()

            # Verify the token is for our app
            if token_info.get("aud") != conf.GOOGLE_CLIENT_ID:
                logger.warning("Google token is for wrong client ID")
                return None

            # Extract user info
            user_info = {
                "email": token_info.get("email"),
                "email_verified": token_info.get("email_verified", False),
                "first_name": token_info.get("given_name", ""),
                "last_name": token_info.get("family_name", ""),
                "google_id": token_info.get("sub"),
            }

            logger.info(f"Google token verified for email: {user_info['email']}")
            return user_info

        except requests.RequestException as e:
            logger.error(f"Error verifying Google token: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying Google token: {e}")
            return None

    @staticmethod
    def verify_facebook_token(token: str) -> Optional[Dict]:
        """
        Verify a Facebook access token and return user info.

        Args:
            token: Facebook access token.

        Returns:
            Dictionary with user info if valid, None otherwise.
        """
        try:
            # First, verify the token
            verify_response = requests.get(
                "https://graph.facebook.com/debug_token",
                params={
                    "input_token": token,
                    "access_token": f"{conf.FACEBOOK_APP_ID}|{conf.FACEBOOK_APP_SECRET}"
                },
                timeout=10
            )

            if verify_response.status_code != 200:
                logger.warning(f"Facebook token verification failed: {verify_response.text}")
                return None

            verify_data = verify_response.json()
            if not verify_data.get("data", {}).get("is_valid", False):
                logger.warning("Facebook token is not valid")
                return None

            # Get user info
            user_response = requests.get(
                "https://graph.facebook.com/me",
                params={
                    "fields": "id,email,first_name,last_name",
                    "access_token": token
                },
                timeout=10
            )

            if user_response.status_code != 200:
                logger.warning(f"Failed to get Facebook user info: {user_response.text}")
                return None

            fb_user = user_response.json()

            user_info = {
                "email": fb_user.get("email"),
                "email_verified": True,  # Facebook verifies emails
                "first_name": fb_user.get("first_name", ""),
                "last_name": fb_user.get("last_name", ""),
                "facebook_id": fb_user.get("id"),
            }

            logger.info(f"Facebook token verified for email: {user_info.get('email')}")
            return user_info

        except requests.RequestException as e:
            logger.error(f"Error verifying Facebook token: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error verifying Facebook token: {e}")
            return None

    @staticmethod
    def verify_twitter_token(oauth_token: str, oauth_token_secret: str) -> Optional[Dict]:
        """
        Verify Twitter OAuth credentials and return user info.

        Note: Twitter uses OAuth 1.0a which is more complex.
        This is a simplified implementation. In production, use a library like tweepy.

        Args:
            oauth_token: Twitter OAuth token.
            oauth_token_secret: Twitter OAuth token secret.

        Returns:
            Dictionary with user info if valid, None otherwise.
        """
        try:
            # This is a placeholder implementation
            # In production, use tweepy or requests-oauthlib for proper OAuth 1.0a flow
            logger.warning("Twitter OAuth is not fully implemented. Please use a proper OAuth library.")

            # Placeholder return
            return None

        except Exception as e:
            logger.error(f"Error verifying Twitter token: {e}")
            return None

    @staticmethod
    def get_or_create_user_from_social(
        provider: str,
        user_info: Dict
    ) -> Tuple[User, bool]:
        """
        Get or create a user from social authentication data.

        Args:
            provider: Social provider name ("google", "facebook", "twitter").
            user_info: User information from the provider.

        Returns:
            Tuple of (user, created).

        Raises:
            ValidationError: If user info is invalid.
        """
        if not user_info.get("email"):
            raise ValidationError("Email is required for social authentication")

        email = user_info["email"]
        provider_id_field = f"{provider}_id"
        provider_id = user_info.get(provider_id_field)

        # Try to find existing user by provider ID
        if provider_id:
            filter_kwargs = {provider_id_field: provider_id}
            try:
                user = User.objects.get(**filter_kwargs)
                logger.info(f"Found existing user by {provider} ID: {email}")
                return user, False
            except User.DoesNotExist:
                pass

        # Try to find existing user by email
        try:
            user = User.objects.get(email=email)

            # Link the social account
            if provider_id:
                setattr(user, provider_id_field, provider_id)

            # Update email verification if provider confirms it
            if user_info.get("email_verified"):
                user.email_verified = True

            # Update name if not set
            if not user.first_name and user_info.get("first_name"):
                user.first_name = user_info["first_name"]
            if not user.last_name and user_info.get("last_name"):
                user.last_name = user_info["last_name"]

            user.save()
            logger.info(f"Linked {provider} account to existing user: {email}")
            return user, False

        except User.DoesNotExist:
            # Create new user
            user_data = {
                "email": email,
                "first_name": user_info.get("first_name", ""),
                "last_name": user_info.get("last_name", ""),
                "email_verified": user_info.get("email_verified", False),
            }

            if provider_id:
                user_data[provider_id_field] = provider_id

            user = User.objects.create_user(**user_data)
            logger.info(f"Created new user from {provider}: {email}")
            return user, True

    @staticmethod
    def google_login(token: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user using Google OAuth.

        Args:
            token: Google OAuth token.

        Returns:
            Tuple of (success: bool, user: Optional[User], message: str).
        """
        user_info = OAuthService.verify_google_token(token)

        if not user_info:
            return False, None, "Invalid Google token"

        try:
            user, created = OAuthService.get_or_create_user_from_social("google", user_info)
            action = "created" if created else "logged in"
            return True, user, f"User {action} successfully via Google"
        except ValidationError as e:
            return False, None, str(e)
        except Exception as e:
            logger.error(f"Error during Google login: {e}")
            return False, None, "Failed to authenticate with Google"

    @staticmethod
    def facebook_login(token: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user using Facebook OAuth.

        Args:
            token: Facebook access token.

        Returns:
            Tuple of (success: bool, user: Optional[User], message: str).
        """
        user_info = OAuthService.verify_facebook_token(token)

        if not user_info:
            return False, None, "Invalid Facebook token"

        try:
            user, created = OAuthService.get_or_create_user_from_social("facebook", user_info)
            action = "created" if created else "logged in"
            return True, user, f"User {action} successfully via Facebook"
        except ValidationError as e:
            return False, None, str(e)
        except Exception as e:
            logger.error(f"Error during Facebook login: {e}")
            return False, None, "Failed to authenticate with Facebook"

    @staticmethod
    def twitter_login(oauth_token: str, oauth_token_secret: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user using Twitter OAuth.

        Args:
            oauth_token: Twitter OAuth token.
            oauth_token_secret: Twitter OAuth token secret.

        Returns:
            Tuple of (success: bool, user: Optional[User], message: str).
        """
        user_info = OAuthService.verify_twitter_token(oauth_token, oauth_token_secret)

        if not user_info:
            return False, None, "Invalid Twitter credentials"

        try:
            user, created = OAuthService.get_or_create_user_from_social("twitter", user_info)
            action = "created" if created else "logged in"
            return True, user, f"User {action} successfully via Twitter"
        except ValidationError as e:
            return False, None, str(e)
        except Exception as e:
            logger.error(f"Error during Twitter login: {e}")
            return False, None, "Failed to authenticate with Twitter"
