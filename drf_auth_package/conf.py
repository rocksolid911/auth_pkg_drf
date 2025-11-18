"""Configuration module for DRF Auth Package."""

import os
from typing import Any, List

from django.conf import settings


def get_setting(name: str, default: Any = None) -> Any:
    """Get a setting value from Django settings with a default fallback."""
    return getattr(settings, name, default)


# Authentication mode: "jwt", "session", or "both"
AUTH_BACKEND_MODE = get_setting("DRF_AUTH_BACKEND_MODE", "jwt")

# JWT Settings
JWT_ACCESS_TOKEN_LIFETIME_MINUTES = get_setting(
    "DRF_AUTH_JWT_ACCESS_TOKEN_LIFETIME_MINUTES", 60
)
JWT_REFRESH_TOKEN_LIFETIME_DAYS = get_setting(
    "DRF_AUTH_JWT_REFRESH_TOKEN_LIFETIME_DAYS", 7
)
JWT_ALGORITHM = get_setting("DRF_AUTH_JWT_ALGORITHM", "HS256")
JWT_SIGNING_KEY = get_setting("DRF_AUTH_JWT_SIGNING_KEY", settings.SECRET_KEY)

# Email Settings
EMAIL_VERIFICATION_REQUIRED = get_setting("DRF_AUTH_EMAIL_VERIFICATION_REQUIRED", True)
EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS = get_setting(
    "DRF_AUTH_EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS", 24
)
PASSWORD_RESET_TOKEN_EXPIRY_HOURS = get_setting(
    "DRF_AUTH_PASSWORD_RESET_TOKEN_EXPIRY_HOURS", 1
)

# Phone Settings
PHONE_VERIFICATION_REQUIRED = get_setting("DRF_AUTH_PHONE_VERIFICATION_REQUIRED", False)
PHONE_OTP_LENGTH = get_setting("DRF_AUTH_PHONE_OTP_LENGTH", 6)
PHONE_OTP_EXPIRY_SECONDS = get_setting("DRF_AUTH_PHONE_OTP_EXPIRY_SECONDS", 300)  # 5 minutes
PHONE_OTP_MAX_ATTEMPTS = get_setting("DRF_AUTH_PHONE_OTP_MAX_ATTEMPTS", 3)

# Social Auth Settings
GOOGLE_CLIENT_ID = get_setting("DRF_AUTH_GOOGLE_CLIENT_ID", os.environ.get("GOOGLE_CLIENT_ID", ""))
GOOGLE_CLIENT_SECRET = get_setting("DRF_AUTH_GOOGLE_CLIENT_SECRET", os.environ.get("GOOGLE_CLIENT_SECRET", ""))

FACEBOOK_APP_ID = get_setting("DRF_AUTH_FACEBOOK_APP_ID", os.environ.get("FACEBOOK_APP_ID", ""))
FACEBOOK_APP_SECRET = get_setting("DRF_AUTH_FACEBOOK_APP_SECRET", os.environ.get("FACEBOOK_APP_SECRET", ""))

TWITTER_API_KEY = get_setting("DRF_AUTH_TWITTER_API_KEY", os.environ.get("TWITTER_API_KEY", ""))
TWITTER_API_SECRET = get_setting("DRF_AUTH_TWITTER_API_SECRET", os.environ.get("TWITTER_API_SECRET", ""))

# Session Settings
SESSION_COOKIE_AGE_SECONDS = get_setting("DRF_AUTH_SESSION_COOKIE_AGE_SECONDS", 1209600)  # 2 weeks

# User Model Settings
USER_REGISTRATION_FIELDS = get_setting(
    "DRF_AUTH_USER_REGISTRATION_FIELDS",
    ["email", "password", "first_name", "last_name"]
)


def get_authentication_classes() -> List[str]:
    """
    Return the appropriate DRF authentication classes based on AUTH_BACKEND_MODE.

    Returns:
        List of authentication class paths as strings.
    """
    mode = AUTH_BACKEND_MODE.lower()

    if mode == "jwt":
        return ["drf_auth_package.authentication.JWTAuthentication"]
    elif mode == "session":
        return ["rest_framework.authentication.SessionAuthentication"]
    elif mode == "both":
        return [
            "drf_auth_package.authentication.JWTAuthentication",
            "rest_framework.authentication.SessionAuthentication",
        ]
    else:
        raise ValueError(
            f"Invalid AUTH_BACKEND_MODE: {mode}. Must be 'jwt', 'session', or 'both'."
        )
