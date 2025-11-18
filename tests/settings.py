"""Test settings for DRF Auth Package."""

import os

SECRET_KEY = "test-secret-key-for-testing-only"

DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_auth_package",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

AUTH_USER_MODEL = "drf_auth_package.User"

AUTHENTICATION_BACKENDS = [
    "drf_auth_package.authentication.EmailBackend",
    "django.contrib.auth.backends.ModelBackend",
]

DRF_AUTH_BACKEND_MODE = "jwt"

from drf_auth_package.conf import get_authentication_classes

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": get_authentication_classes(),
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
}

# Disable email verification for tests
DRF_AUTH_EMAIL_VERIFICATION_REQUIRED = False
DRF_AUTH_PHONE_VERIFICATION_REQUIRED = False

# Use default language
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
