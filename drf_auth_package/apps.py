"""Django app configuration for DRF Auth Package."""

from django.apps import AppConfig


class DrfAuthPackageConfig(AppConfig):
    """Configuration for the DRF Auth Package application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "drf_auth_package"
    verbose_name = "DRF Authentication Package"

    def ready(self):
        """Import signals and perform any initialization."""
        # Import signals here if needed
        pass
