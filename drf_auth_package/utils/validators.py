"""Custom validators for authentication fields."""

import re
from typing import Optional

from django.core.exceptions import ValidationError
from django.core.validators import validate_email as django_validate_email
from django.utils.translation import gettext_lazy as _


def validate_email(email: str) -> None:
    """
    Validate email format.

    Args:
        email: Email address to validate.

    Raises:
        ValidationError: If email is invalid.
    """
    try:
        django_validate_email(email)
    except ValidationError:
        raise ValidationError(_("Enter a valid email address."))


def validate_phone_number(phone_number: str) -> None:
    """
    Validate phone number format.

    Args:
        phone_number: Phone number to validate.

    Raises:
        ValidationError: If phone number is invalid.
    """
    pattern = r'^\+?1?\d{9,15}$'
    if not re.match(pattern, phone_number):
        raise ValidationError(
            _("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
        )


def validate_password_strength(password: str) -> None:
    """
    Validate password strength.

    Requirements:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit

    Args:
        password: Password to validate.

    Raises:
        ValidationError: If password doesn't meet requirements.
    """
    if len(password) < 8:
        raise ValidationError(_("Password must be at least 8 characters long."))

    if not re.search(r'[A-Z]', password):
        raise ValidationError(_("Password must contain at least one uppercase letter."))

    if not re.search(r'[a-z]', password):
        raise ValidationError(_("Password must contain at least one lowercase letter."))

    if not re.search(r'\d', password):
        raise ValidationError(_("Password must contain at least one digit."))


def validate_otp(otp: str, expected_length: int = 6) -> None:
    """
    Validate OTP format.

    Args:
        otp: OTP to validate.
        expected_length: Expected length of the OTP.

    Raises:
        ValidationError: If OTP is invalid.
    """
    if len(otp) != expected_length:
        raise ValidationError(_(f"OTP must be {expected_length} digits."))

    if not otp.isdigit():
        raise ValidationError(_("OTP must contain only digits."))
