import uuid
from typing import Optional

from django.contrib.auth.backends import BaseBackend
from django.http import HttpRequest

from fief_client.integrations.django.models import FiefUser


class FiefBackend(BaseBackend):
    def authenticate(  # type: ignore
        self, request: Optional[HttpRequest], **kwargs
    ) -> Optional[FiefUser]:
        fief_id: Optional[uuid.UUID] = kwargs.get("fief_id")
        email: Optional[str] = kwargs.get("email")

        if fief_id is None:
            return None

        try:
            user = FiefUser.objects.get(fief_id=fief_id)
        except FiefUser.DoesNotExist:
            user = FiefUser.objects.create(fief_id=fief_id, email=email)

        if email is not None and user.email != email:
            user.email = email
            user.save()

        return user

    def get_user(self, user_id) -> Optional[FiefUser]:  # type: ignore
        try:
            return FiefUser.objects.get(pk=user_id)
        except FiefUser.DoesNotExist:
            return None
