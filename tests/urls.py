"""Test URLs configuration."""

from django.urls import path, include

urlpatterns = [
    path("api/", include("drf_auth_package.urls")),
]
