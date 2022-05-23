from functools import lru_cache

from django.conf import settings

from fief_client.client import Fief


@lru_cache()
def get_fief_client() -> Fief:
    return Fief(
        settings.FIEF_BASE_URL, settings.FIEF_CLIENT_ID, settings.FIEF_CLIENT_SECRET
    )
