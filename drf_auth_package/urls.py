"""URL configuration for DRF Auth Package using Routers."""

from rest_framework.routers import DefaultRouter

from drf_auth_package.views import (
    AuthViewSet,
    EmailViewSet,
    PasswordViewSet,
    PhoneViewSet,
    SocialAuthViewSet,
    TokenViewSet,
)

app_name = "drf_auth_package"

# Create router
router = DefaultRouter(trailing_slash=False)

# Register ViewSets
# Note: We use empty string as prefix and specify full paths in @action decorators
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'auth/password', PasswordViewSet, basename='password')
router.register(r'auth/email', EmailViewSet, basename='email')
router.register(r'auth/phone', PhoneViewSet, basename='phone')
router.register(r'auth/social', SocialAuthViewSet, basename='social')
router.register(r'auth/jwt', TokenViewSet, basename='jwt')

urlpatterns = router.urls
