"""Serializers for DRF Auth Package."""

from typing import Dict

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from drf_auth_package.models import User
from drf_auth_package.utils.validators import (
    validate_email,
    validate_phone_number,
    validate_otp,
)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "phone_number",
            "first_name",
            "last_name",
            "email_verified",
            "phone_verified",
            "is_active",
            "date_joined",
            "last_login",
        ]
        read_only_fields = [
            "id",
            "email_verified",
            "phone_verified",
            "is_active",
            "date_joined",
            "last_login",
        ]


class RegisterSerializer(serializers.Serializer):
    """Serializer for user registration."""

    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    password_confirm = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=17, required=False, allow_blank=True)

    def validate_email(self, value: str) -> str:
        """Validate email."""
        validate_email(value)

        # Check if email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")

        return value

    def validate_phone_number(self, value: str) -> str:
        """Validate phone number."""
        if value:
            validate_phone_number(value)

            # Check if phone already exists
            if User.objects.filter(phone_number=value).exists():
                raise serializers.ValidationError("A user with this phone number already exists.")

        return value

    def validate_password(self, value: str) -> str:
        """Validate password strength."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, data: Dict) -> Dict:
        """Validate password confirmation."""
        if data.get("password") != data.get("password_confirm"):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return data

    def create(self, validated_data: Dict) -> User:
        """Create a new user."""
        validated_data.pop("password_confirm")
        password = validated_data.pop("password")

        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        return user


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""

    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""

    old_password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    new_password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    new_password_confirm = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})

    def validate_new_password(self, value: str) -> str:
        """Validate new password strength."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, data: Dict) -> Dict:
        """Validate password confirmation."""
        if data.get("new_password") != data.get("new_password_confirm"):
            raise serializers.ValidationError({"new_password_confirm": "Passwords do not match."})
        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""

    email = serializers.EmailField(required=True)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation."""

    token = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    new_password_confirm = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})

    def validate_new_password(self, value: str) -> str:
        """Validate new password strength."""
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, data: Dict) -> Dict:
        """Validate password confirmation."""
        if data.get("new_password") != data.get("new_password_confirm"):
            raise serializers.ValidationError({"new_password_confirm": "Passwords do not match."})
        return data


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification."""

    token = serializers.CharField(required=True)


class PhoneOTPRequestSerializer(serializers.Serializer):
    """Serializer for phone OTP request."""

    phone_number = serializers.CharField(max_length=17, required=True)

    def validate_phone_number(self, value: str) -> str:
        """Validate phone number."""
        validate_phone_number(value)
        return value


class PhoneOTPVerifySerializer(serializers.Serializer):
    """Serializer for phone OTP verification."""

    phone_number = serializers.CharField(max_length=17, required=True)
    otp = serializers.CharField(max_length=10, required=True)

    def validate_phone_number(self, value: str) -> str:
        """Validate phone number."""
        validate_phone_number(value)
        return value

    def validate_otp(self, value: str) -> str:
        """Validate OTP."""
        from drf_auth_package.conf import PHONE_OTP_LENGTH
        validate_otp(value, PHONE_OTP_LENGTH)
        return value


class PhoneLoginSerializer(serializers.Serializer):
    """Serializer for phone-based login."""

    phone_number = serializers.CharField(max_length=17, required=True)
    otp = serializers.CharField(max_length=10, required=True)

    def validate_phone_number(self, value: str) -> str:
        """Validate phone number."""
        validate_phone_number(value)
        return value

    def validate_otp(self, value: str) -> str:
        """Validate OTP."""
        from drf_auth_package.conf import PHONE_OTP_LENGTH
        validate_otp(value, PHONE_OTP_LENGTH)
        return value


class GoogleLoginSerializer(serializers.Serializer):
    """Serializer for Google OAuth login."""

    token = serializers.CharField(required=True)


class FacebookLoginSerializer(serializers.Serializer):
    """Serializer for Facebook OAuth login."""

    token = serializers.CharField(required=True)


class TwitterLoginSerializer(serializers.Serializer):
    """Serializer for Twitter OAuth login."""

    oauth_token = serializers.CharField(required=True)
    oauth_token_secret = serializers.CharField(required=True)


class TokenRefreshSerializer(serializers.Serializer):
    """Serializer for JWT token refresh."""

    refresh = serializers.CharField(required=True)


class TokenVerifySerializer(serializers.Serializer):
    """Serializer for JWT token verification."""

    token = serializers.CharField(required=True)
