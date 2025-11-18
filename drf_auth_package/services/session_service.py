"""Session-based authentication service."""

import logging
from typing import Optional

from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.http import HttpRequest

from drf_auth_package.models import User

logger = logging.getLogger(__name__)


class SessionService:
    """Service for session-based authentication."""

    @staticmethod
    def login_user(request: HttpRequest, email: str, password: str) -> Optional[User]:
        """
        Authenticate and log in a user using session authentication.

        Args:
            request: The HTTP request object.
            email: User's email address.
            password: User's password.

        Returns:
            User object if authentication successful, None otherwise.
        """
        user = authenticate(request, username=email, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                logger.info(f"User {email} logged in successfully (session-based)")
                return user
            else:
                logger.warning(f"Inactive user attempted to log in: {email}")
                return None
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            return None

    @staticmethod
    def logout_user(request: HttpRequest) -> None:
        """
        Log out a user and destroy their session.

        Args:
            request: The HTTP request object.
        """
        if request.user.is_authenticated:
            email = request.user.email
            logout(request)
            logger.info(f"User {email} logged out successfully (session-based)")
        else:
            logger.warning("Logout attempted by unauthenticated user")

    @staticmethod
    def get_user_sessions(user: User) -> list:
        """
        Get all active sessions for a user.

        Args:
            user: The user to get sessions for.

        Returns:
            List of session objects.
        """
        user_sessions = []
        all_sessions = Session.objects.filter(expire_date__gte=timezone.now())

        for session in all_sessions:
            session_data = session.get_decoded()
            if session_data.get('_auth_user_id') == str(user.id):
                user_sessions.append(session)

        return user_sessions

    @staticmethod
    def revoke_all_sessions(user: User) -> int:
        """
        Revoke all sessions for a user.

        Args:
            user: The user whose sessions to revoke.

        Returns:
            Number of sessions revoked.
        """
        sessions = SessionService.get_user_sessions(user)
        count = len(sessions)

        for session in sessions:
            session.delete()

        logger.info(f"Revoked {count} sessions for user {user.email}")
        return count
