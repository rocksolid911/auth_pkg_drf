"""Token generation and validation utilities."""

import secrets
import string
from datetime import timedelta
from typing import Tuple

from django.utils import timezone


def generate_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Args:
        length: Length of the token to generate.

    Returns:
        A secure random token string.
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_otp(length: int = 6) -> str:
    """
    Generate a numeric OTP.

    Args:
        length: Length of the OTP to generate.

    Returns:
        A numeric OTP string.
    """
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def create_expiry_time(hours: int = 0, minutes: int = 0, seconds: int = 0) -> timezone.datetime:
    """
    Create an expiry datetime from now.

    Args:
        hours: Number of hours until expiry.
        minutes: Number of minutes until expiry.
        seconds: Number of seconds until expiry.

    Returns:
        A datetime object representing the expiry time.
    """
    delta = timedelta(hours=hours, minutes=minutes, seconds=seconds)
    return timezone.now() + delta


def create_email_verification_token(user) -> Tuple[str, timezone.datetime]:
    """
    Create an email verification token for a user.

    Args:
        user: The user to create the token for.

    Returns:
        A tuple of (token, expiry_time).
    """
    from drf_auth_package.conf import EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS

    token = generate_token(64)
    expiry = create_expiry_time(hours=EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS)

    return token, expiry


def create_password_reset_token(user) -> Tuple[str, timezone.datetime]:
    """
    Create a password reset token for a user.

    Args:
        user: The user to create the token for.

    Returns:
        A tuple of (token, expiry_time).
    """
    from drf_auth_package.conf import PASSWORD_RESET_TOKEN_EXPIRY_HOURS

    token = generate_token(64)
    expiry = create_expiry_time(hours=PASSWORD_RESET_TOKEN_EXPIRY_HOURS)

    return token, expiry


def create_phone_otp(phone_number: str) -> Tuple[str, timezone.datetime]:
    """
    Create a phone OTP.

    Args:
        phone_number: The phone number to create the OTP for.

    Returns:
        A tuple of (otp, expiry_time).
    """
    from drf_auth_package.conf import PHONE_OTP_LENGTH, PHONE_OTP_EXPIRY_SECONDS

    otp = generate_otp(PHONE_OTP_LENGTH)
    expiry = create_expiry_time(seconds=PHONE_OTP_EXPIRY_SECONDS)

    return otp, expiry
