from functools import wraps
from typing import List, Optional

from flask import g, request

from fief_client import (
    Fief,
    FiefAccessTokenExpired,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingScope,
)


class FiefAuthError(Exception):
    pass


class FiefAuthUnauthorized(FiefAuthError):
    pass


class FiefAuthForbidden(FiefAuthError):
    pass


class FiefAuth:
    def __init__(self, client: Fief) -> None:
        self.client = client

    def current_user(self, *, scope: Optional[List[str]] = None):
        def _current_user(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = self.get_token()
                if token is None:
                    raise FiefAuthUnauthorized()

                try:
                    info = self.client.validate_access_token(
                        token, required_scope=scope
                    )
                except (FiefAccessTokenInvalid, FiefAccessTokenExpired) as e:
                    raise FiefAuthUnauthorized() from e
                except FiefAccessTokenMissingScope as e:
                    raise FiefAuthForbidden() from e

                g.user = info

                return f(*args, **kwargs)

            return decorated_function

        return _current_user

    def get_token(self) -> Optional[str]:
        authorization = request.headers.get("Authorization")
        if authorization is None:
            return None
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        return parts[1]


__all__ = ["FiefAuth", "FiefAuthError", "FiefAuthUnauthorized", "FiefAuthForbidden"]
