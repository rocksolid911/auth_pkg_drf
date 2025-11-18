"""URL configuration for DRF Auth Package."""

from django.urls import path

from drf_auth_package.views import (
    EmailResendVerificationView,
    EmailVerifyView,
    FacebookLoginView,
    GoogleLoginView,
    LoginView,
    LogoutView,
    MeView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    PhoneLoginView,
    PhoneRequestOTPView,
    PhoneVerifyOTPView,
    RegisterView,
    TokenObtainView,
    TokenRefreshView,
    TokenVerifyView,
    TwitterLoginView,
)

app_name = "drf_auth_package"

urlpatterns = [
    # Registration and login
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/me/", MeView.as_view(), name="me"),

    # Password management
    path("auth/password/change/", PasswordChangeView.as_view(), name="password-change"),
    path("auth/password/reset/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("auth/password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),

    # Email verification
    path("auth/email/verify/", EmailVerifyView.as_view(), name="email-verify"),
    path("auth/email/verify/resend/", EmailResendVerificationView.as_view(), name="email-verify-resend"),

    # Phone authentication
    path("auth/phone/request-otp/", PhoneRequestOTPView.as_view(), name="phone-request-otp"),
    path("auth/phone/verify-otp/", PhoneVerifyOTPView.as_view(), name="phone-verify-otp"),
    path("auth/phone/login/", PhoneLoginView.as_view(), name="phone-login"),

    # Social authentication
    path("auth/social/google/", GoogleLoginView.as_view(), name="google-login"),
    path("auth/social/facebook/", FacebookLoginView.as_view(), name="facebook-login"),
    path("auth/social/twitter/", TwitterLoginView.as_view(), name="twitter-login"),

    # JWT endpoints
    path("auth/jwt/token/", TokenObtainView.as_view(), name="token-obtain"),
    path("auth/jwt/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/jwt/token/verify/", TokenVerifyView.as_view(), name="token-verify"),
]
