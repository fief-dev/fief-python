from django.apps import AppConfig
from django.core.exceptions import ImproperlyConfigured

REQUIRED_SETTINGS = [
    "FIEF_BASE_URL",
    "FIEF_CLIENT_ID",
    "FIEF_CLIENT_SECRET",
    "FIEF_SCOPE",
]


class FiefAuthImproperlyConfigured(ImproperlyConfigured):
    pass


class FiefAuthConfig(AppConfig):
    default = True
    default_auto_field = "django.db.models.BigAutoField"
    name = "fief_client.integrations.django"
    label = "fief_auth"

    def ready(self):
        from django.conf import settings

        for setting in REQUIRED_SETTINGS:
            if getattr(settings, setting, None) is None:
                raise FiefAuthImproperlyConfigured(
                    f"The setting {setting} is missing"
                )  # pragma: no cover

        silenced_system_checks = getattr(settings, "SILENCED_SYSTEM_CHECKS", [])
        silenced_system_checks.append("auth.W004")
        setattr(settings, "SILENCED_SYSTEM_CHECKS", silenced_system_checks)
