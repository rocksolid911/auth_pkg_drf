"""Views for DRF Auth Package."""

import logging

import jwt
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_auth_package import conf
from drf_auth_package.models import EmailVerificationToken, PasswordResetToken, User
from drf_auth_package.serializers import (
    EmailVerificationSerializer,
    FacebookLoginSerializer,
    GoogleLoginSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    PhoneLoginSerializer,
    PhoneOTPRequestSerializer,
    PhoneOTPVerifySerializer,
    RegisterSerializer,
    TokenRefreshSerializer,
    TokenVerifySerializer,
    TwitterLoginSerializer,
    UserSerializer,
)
from drf_auth_package.services.jwt_service import JWTService
from drf_auth_package.services.oauth_service import OAuthService
from drf_auth_package.services.phone_service import PhoneService
from drf_auth_package.services.session_service import SessionService
from drf_auth_package.utils.tokens import (
    create_email_verification_token,
    create_password_reset_token,
)

logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str:
    """Get client IP address from request."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def get_user_agent(request: Request) -> str:
    """Get user agent from request."""
    return request.META.get("HTTP_USER_AGENT", "")


class RegisterView(APIView):
    """User registration endpoint."""

    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request: Request) -> Response:
        """Register a new user."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        logger.info(f"New user registered: {user.email}")

        # Send email verification if required
        if conf.EMAIL_VERIFICATION_REQUIRED:
            token, expiry = create_email_verification_token(user)
            EmailVerificationToken.objects.create(
                user=user,
                token=token,
                expires_at=expiry
            )

            # TODO: Send email with verification link
            # Example: verification_link = request.build_absolute_uri(
            #     reverse('auth-email-verify') + f'?token={token}'
            # )
            logger.info(f"Email verification token created for {user.email}: {token}")

        # Return user data and tokens based on auth mode
        response_data = {
            "user": UserSerializer(user).data,
            "message": "User registered successfully.",
        }

        if conf.EMAIL_VERIFICATION_REQUIRED:
            response_data["message"] += " Please verify your email."

        # Generate tokens if JWT mode
        if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
            tokens = JWTService.generate_token_pair(
                user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            response_data["tokens"] = tokens

        return Response(response_data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    """User login endpoint."""

    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request: Request) -> Response:
        """Log in a user."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        # Check auth mode
        auth_mode = conf.AUTH_BACKEND_MODE

        if auth_mode == "session":
            # Session-based login
            user = SessionService.login_user(request._request, email, password)
            if not user:
                return Response(
                    {"error": "Invalid credentials or inactive account."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            return Response({
                "user": UserSerializer(user).data,
                "message": "Login successful.",
            }, status=status.HTTP_200_OK)

        else:  # JWT or both
            # Authenticate user
            from django.contrib.auth import authenticate
            user = authenticate(request._request, username=email, password=password)

            if not user:
                return Response(
                    {"error": "Invalid credentials."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not user.is_active:
                return Response(
                    {"error": "Account is inactive."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Generate tokens
            tokens = JWTService.generate_token_pair(
                user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )

            logger.info(f"User {email} logged in successfully (JWT)")

            return Response({
                "user": UserSerializer(user).data,
                "tokens": tokens,
                "message": "Login successful.",
            }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """User logout endpoint."""

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Log out a user."""
        auth_mode = conf.AUTH_BACKEND_MODE

        if auth_mode == "session":
            SessionService.logout_user(request._request)
        elif auth_mode in ["jwt", "both"]:
            # Revoke all refresh tokens
            JWTService.revoke_all_user_tokens(request.user)

        logger.info(f"User {request.user.email} logged out")

        return Response({
            "message": "Logout successful."
        }, status=status.HTTP_200_OK)


class MeView(APIView):
    """Get current user endpoint."""

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """Get current user information."""
        return Response({
            "user": UserSerializer(request.user).data
        }, status=status.HTTP_200_OK)


class PasswordChangeView(APIView):
    """Password change endpoint."""

    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer

    def post(self, request: Request) -> Response:
        """Change user password."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user

        # Verify old password
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response(
                {"error": "Old password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set new password
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        # Revoke all tokens/sessions for security
        if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
            JWTService.revoke_all_user_tokens(user)

        logger.info(f"Password changed for user {user.email}")

        return Response({
            "message": "Password changed successfully. Please log in again."
        }, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    """Password reset request endpoint."""

    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request: Request) -> Response:
        """Request a password reset."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)

            # Create reset token
            token, expiry = create_password_reset_token(user)
            PasswordResetToken.objects.create(
                user=user,
                token=token,
                expires_at=expiry
            )

            # TODO: Send email with reset link
            # Example: reset_link = request.build_absolute_uri(
            #     reverse('auth-password-reset-confirm') + f'?token={token}'
            # )
            logger.info(f"Password reset token created for {user.email}: {token}")

        except User.DoesNotExist:
            # Don't reveal that the user doesn't exist
            logger.warning(f"Password reset requested for non-existent email: {email}")

        # Always return success to prevent email enumeration
        return Response({
            "message": "If an account with that email exists, a password reset link has been sent."
        }, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    """Password reset confirmation endpoint."""

    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request: Request) -> Response:
        """Confirm password reset with token."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        try:
            reset_token = PasswordResetToken.objects.get(token=token)

            if not reset_token.is_valid():
                return Response(
                    {"error": "Invalid or expired token."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Reset password
            user = reset_token.user
            user.set_password(new_password)
            user.save()

            # Mark token as used
            reset_token.used = True
            reset_token.save()

            # Revoke all tokens/sessions
            if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
                JWTService.revoke_all_user_tokens(user)

            logger.info(f"Password reset for user {user.email}")

            return Response({
                "message": "Password reset successfully. Please log in with your new password."
            }, status=status.HTTP_200_OK)

        except PasswordResetToken.DoesNotExist:
            return Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST
            )


class EmailVerifyView(APIView):
    """Email verification endpoint."""

    permission_classes = [AllowAny]
    serializer_class = EmailVerificationSerializer

    def post(self, request: Request) -> Response:
        """Verify email with token."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data["token"]

        try:
            verification_token = EmailVerificationToken.objects.get(token=token)

            if not verification_token.is_valid():
                return Response(
                    {"error": "Invalid or expired token."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Verify email
            user = verification_token.user
            user.email_verified = True
            user.save()

            # Mark token as used
            verification_token.used = True
            verification_token.save()

            logger.info(f"Email verified for user {user.email}")

            return Response({
                "message": "Email verified successfully."
            }, status=status.HTTP_200_OK)

        except EmailVerificationToken.DoesNotExist:
            return Response(
                {"error": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST
            )


class EmailResendVerificationView(APIView):
    """Resend email verification endpoint."""

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """Resend email verification."""
        user = request.user

        if user.email_verified:
            return Response(
                {"message": "Email is already verified."},
                status=status.HTTP_200_OK
            )

        # Invalidate old tokens
        EmailVerificationToken.objects.filter(user=user, used=False).update(used=True)

        # Create new token
        token, expiry = create_email_verification_token(user)
        EmailVerificationToken.objects.create(
            user=user,
            token=token,
            expires_at=expiry
        )

        # TODO: Send email
        logger.info(f"Email verification resent for {user.email}: {token}")

        return Response({
            "message": "Verification email sent."
        }, status=status.HTTP_200_OK)


class PhoneRequestOTPView(APIView):
    """Phone OTP request endpoint."""

    permission_classes = [AllowAny]
    serializer_class = PhoneOTPRequestSerializer

    def post(self, request: Request) -> Response:
        """Request OTP for phone verification."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone_number = serializer.validated_data["phone_number"]

        # Get user if authenticated
        user = request.user if request.user.is_authenticated else None

        success, message = PhoneService.send_otp(phone_number, user)

        if success:
            return Response({"message": message}, status=status.HTTP_200_OK)
        else:
            return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)


class PhoneVerifyOTPView(APIView):
    """Phone OTP verification endpoint."""

    permission_classes = [AllowAny]
    serializer_class = PhoneOTPVerifySerializer

    def post(self, request: Request) -> Response:
        """Verify phone OTP."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone_number = serializer.validated_data["phone_number"]
        otp = serializer.validated_data["otp"]

        success, user, message = PhoneService.verify_otp(phone_number, otp)

        if success:
            return Response({"message": message}, status=status.HTTP_200_OK)
        else:
            return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)


class PhoneLoginView(APIView):
    """Phone-based login endpoint."""

    permission_classes = [AllowAny]
    serializer_class = PhoneLoginSerializer

    def post(self, request: Request) -> Response:
        """Log in using phone number and OTP."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone_number = serializer.validated_data["phone_number"]
        otp = serializer.validated_data["otp"]

        success, user, message = PhoneService.phone_login(phone_number, otp)

        if not success:
            return Response({"error": message}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate tokens based on auth mode
        response_data = {
            "user": UserSerializer(user).data,
            "message": message,
        }

        if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
            tokens = JWTService.generate_token_pair(
                user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            response_data["tokens"] = tokens

        return Response(response_data, status=status.HTTP_200_OK)


class GoogleLoginView(APIView):
    """Google OAuth login endpoint."""

    permission_classes = [AllowAny]
    serializer_class = GoogleLoginSerializer

    def post(self, request: Request) -> Response:
        """Log in with Google OAuth."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data["token"]

        success, user, message = OAuthService.google_login(token)

        if not success:
            return Response({"error": message}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate tokens based on auth mode
        response_data = {
            "user": UserSerializer(user).data,
            "message": message,
        }

        if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
            tokens = JWTService.generate_token_pair(
                user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            response_data["tokens"] = tokens

        return Response(response_data, status=status.HTTP_200_OK)


class FacebookLoginView(APIView):
    """Facebook OAuth login endpoint."""

    permission_classes = [AllowAny]
    serializer_class = FacebookLoginSerializer

    def post(self, request: Request) -> Response:
        """Log in with Facebook OAuth."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data["token"]

        success, user, message = OAuthService.facebook_login(token)

        if not success:
            return Response({"error": message}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate tokens based on auth mode
        response_data = {
            "user": UserSerializer(user).data,
            "message": message,
        }

        if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
            tokens = JWTService.generate_token_pair(
                user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            response_data["tokens"] = tokens

        return Response(response_data, status=status.HTTP_200_OK)


class TwitterLoginView(APIView):
    """Twitter OAuth login endpoint."""

    permission_classes = [AllowAny]
    serializer_class = TwitterLoginSerializer

    def post(self, request: Request) -> Response:
        """Log in with Twitter OAuth."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        oauth_token = serializer.validated_data["oauth_token"]
        oauth_token_secret = serializer.validated_data["oauth_token_secret"]

        success, user, message = OAuthService.twitter_login(oauth_token, oauth_token_secret)

        if not success:
            return Response({"error": message}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate tokens based on auth mode
        response_data = {
            "user": UserSerializer(user).data,
            "message": message,
        }

        if conf.AUTH_BACKEND_MODE in ["jwt", "both"]:
            tokens = JWTService.generate_token_pair(
                user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request)
            )
            response_data["tokens"] = tokens

        return Response(response_data, status=status.HTTP_200_OK)


class TokenObtainView(APIView):
    """JWT token obtain endpoint."""

    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request: Request) -> Response:
        """Obtain JWT token pair."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        # Authenticate user
        from django.contrib.auth import authenticate
        user = authenticate(request._request, username=email, password=password)

        if not user:
            return Response(
                {"error": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            return Response(
                {"error": "Account is inactive."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Generate tokens
        tokens = JWTService.generate_token_pair(
            user,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )

        return Response(tokens, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    """JWT token refresh endpoint."""

    permission_classes = [AllowAny]
    serializer_class = TokenRefreshSerializer

    def post(self, request: Request) -> Response:
        """Refresh JWT access token."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        refresh_token = serializer.validated_data["refresh"]

        try:
            access_token, user = JWTService.refresh_access_token(refresh_token)

            return Response({
                "access": access_token
            }, status=status.HTTP_200_OK)

        except jwt.InvalidTokenError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )


class TokenVerifyView(APIView):
    """JWT token verification endpoint."""

    permission_classes = [AllowAny]
    serializer_class = TokenVerifySerializer

    def post(self, request: Request) -> Response:
        """Verify JWT token."""
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data["token"]

        try:
            payload = JWTService.verify_token(token, token_type="access")

            return Response({
                "valid": True,
                "payload": payload
            }, status=status.HTTP_200_OK)

        except jwt.InvalidTokenError as e:
            return Response(
                {"valid": False, "error": str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )
