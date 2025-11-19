"""Models for DRF Auth Package."""

import uuid
from datetime import timedelta
from typing import Optional

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""

    def create_user(
        self,
        email: str,
        password: Optional[str] = None,
        **extra_fields
    ):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError(_("The Email field must be set"))

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(
        self,
        email: str,
        password: Optional[str] = None,
        **extra_fields
    ):
        """Create and return a superuser with an email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("email_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model using email as the primary identifier."""

    # Phone number validator
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message=_("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
    )

    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_("email address"), unique=True, db_index=True)
    phone_number = models.CharField(
        _("phone number"),
        validators=[phone_regex],
        max_length=17,
        blank=True,
        null=True,
        unique=True,
        db_index=True
    )

    # User information
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)

    # Verification flags
    email_verified = models.BooleanField(_("email verified"), default=False)
    phone_verified = models.BooleanField(_("phone verified"), default=False)

    # Status flags
    is_active = models.BooleanField(_("active"), default=True)
    is_staff = models.BooleanField(_("staff status"), default=False)

    # Timestamps
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)
    last_login = models.DateTimeField(_("last login"), null=True, blank=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    # Social auth fields
    google_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    facebook_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    twitter_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        db_table = "drf_auth_users"
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["phone_number"]),
        ]

    def __str__(self) -> str:
        return self.email

    def get_full_name(self) -> str:
        """Return the first_name plus the last_name, with a space in between."""
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()

    def get_short_name(self) -> str:
        """Return the short name for the user."""
        return self.first_name


class EmailVerificationToken(models.Model):
    """Token for email verification."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="email_verification_tokens")
    token = models.CharField(max_length=255, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        verbose_name = _("email verification token")
        verbose_name_plural = _("email verification tokens")
        db_table = "drf_auth_email_verification_tokens"

    def is_valid(self) -> bool:
        """Check if the token is still valid."""
        return not self.used and timezone.now() < self.expires_at

    def __str__(self) -> str:
        return f"Email verification token for {self.user.email}"


class PasswordResetToken(models.Model):
    """Token for password reset."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token = models.CharField(max_length=255, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        verbose_name = _("password reset token")
        verbose_name_plural = _("password reset tokens")
        db_table = "drf_auth_password_reset_tokens"

    def is_valid(self) -> bool:
        """Check if the token is still valid."""
        return not self.used and timezone.now() < self.expires_at

    def __str__(self) -> str:
        return f"Password reset token for {self.user.email}"


class PhoneOTP(models.Model):
    """OTP for phone verification and authentication."""

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="phone_otps",
        null=True,
        blank=True
    )
    phone_number = models.CharField(max_length=17, db_index=True)
    otp = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)

    class Meta:
        verbose_name = _("phone OTP")
        verbose_name_plural = _("phone OTPs")
        db_table = "drf_auth_phone_otps"
        indexes = [
            models.Index(fields=["phone_number", "verified"]),
        ]

    def is_valid(self) -> bool:
        """Check if the OTP is still valid."""
        from drf_auth_package.conf import PHONE_OTP_MAX_ATTEMPTS
        return (
            not self.verified
            and timezone.now() < self.expires_at
            and self.attempts < PHONE_OTP_MAX_ATTEMPTS
        )

    def __str__(self) -> str:
        return f"OTP for {self.phone_number}"


class RefreshToken(models.Model):
    """Store refresh tokens for JWT authentication."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="refresh_tokens")
    token = models.CharField(max_length=500, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)

    # For tracking and security
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        verbose_name = _("refresh token")
        verbose_name_plural = _("refresh tokens")
        db_table = "drf_auth_refresh_tokens"
        indexes = [
            models.Index(fields=["token"]),
            models.Index(fields=["user", "revoked"]),
        ]

    def is_valid(self) -> bool:
        """Check if the refresh token is still valid."""
        return not self.revoked and timezone.now() < self.expires_at

    def __str__(self) -> str:
        return f"Refresh token for {self.user.email}"
