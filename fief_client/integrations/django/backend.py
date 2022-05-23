import uuid
from typing import Any, Dict, Optional

from django.contrib.auth.backends import BaseBackend
from django.http import HttpRequest

from fief_client.integrations.django.models import FiefUser


class FiefBackend(BaseBackend):
    def authenticate(  # type: ignore
        self, request: Optional[HttpRequest], **kwargs
    ) -> Optional[FiefUser]:
        fief_id: Optional[uuid.UUID] = kwargs.get("fief_id")
        fief_tenant_id: Optional[uuid.UUID] = kwargs.get("fief_tenant_id")
        fields: Optional[Dict[str, Any]] = kwargs.get("fields")
        email: Optional[str] = kwargs.get("email")

        if fief_id is None:
            return None

        defaults: Dict[str, Any] = {}
        if fief_tenant_id is not None:
            defaults["fief_tenant_id"] = fief_tenant_id
        if email is not None:
            defaults["email"] = email
        if fields is not None:
            defaults["fields"] = fields
        user, _ = FiefUser.objects.update_or_create(fief_id=fief_id, defaults=defaults)

        return user

    def get_user(self, user_id) -> Optional[FiefUser]:  # type: ignore
        try:
            return FiefUser.objects.get(pk=user_id)
        except FiefUser.DoesNotExist:
            return None
