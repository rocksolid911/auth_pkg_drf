"""Custom permissions for DRF Auth Package."""

from rest_framework import permissions


class IsEmailVerified(permissions.BasePermission):
    """
    Permission to only allow users with verified email.
    """

    message = "Email verification required."

    def has_permission(self, request, view):
        """Check if user has verified email."""
        return (
            request.user
            and request.user.is_authenticated
            and request.user.email_verified
        )


class IsPhoneVerified(permissions.BasePermission):
    """
    Permission to only allow users with verified phone number.
    """

    message = "Phone verification required."

    def has_permission(self, request, view):
        """Check if user has verified phone number."""
        return (
            request.user
            and request.user.is_authenticated
            and request.user.phone_verified
        )
