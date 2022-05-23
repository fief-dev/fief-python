from django.contrib.auth.models import PermissionsMixin
from django.core.mail import send_mail
from django.db import models
from django.utils.translation import gettext_lazy as _


class FiefUserManager(models.Manager):
    pass


class FiefUser(PermissionsMixin):
    fief_id = models.UUIDField(unique=True)
    email = models.EmailField(unique=True)
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )

    REQUIRED_FIELDS = ["fief_id"]
    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"

    objects = FiefUserManager()

    @property
    def is_anonymous(self) -> bool:
        """
        Always return False. This is a way of comparing User objects to
        anonymous users.
        """
        return False

    @property
    def is_authenticated(self) -> bool:
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

    @property
    def is_active(self) -> bool:
        return True

    def get_full_name(self) -> str:
        """
        Return the first_name plus the last_name, with a space in between.
        """
        return self.email

    def get_short_name(self) -> str:
        """Return the short name for the user."""
        return self.email

    def email_user(self, subject, message, from_email=None, **kwargs) -> None:
        """Send an email to this user."""
        send_mail(
            subject, message, from_email, [self.email], **kwargs
        )  # pragma: no cover

    def get_username(self) -> str:
        """Return the username for this User."""
        return getattr(self, self.USERNAME_FIELD)

    def __str__(self) -> str:
        return self.get_username()
