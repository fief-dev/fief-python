from functools import wraps
from typing import Callable, List, Optional

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


TokenGetter = Callable[[], Optional[str]]


def get_authorization_scheme_token(*, scheme: str = "bearer") -> TokenGetter:
    def _get_authorization_scheme_token():
        authorization = request.headers.get("Authorization")
        if authorization is None:
            return None
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != scheme.lower():
            return None
        return parts[1]

    return _get_authorization_scheme_token


def get_cookie(cookie_name: str) -> TokenGetter:
    def _get_cookie():
        return request.cookies.get(cookie_name)

    return _get_cookie


class FiefAuth:
    def __init__(self, client: Fief, token_getter: TokenGetter) -> None:
        self.client = client
        self.token_getter = token_getter

    def current_user(self, *, scope: Optional[List[str]] = None):
        def _current_user(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = self.token_getter()
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


__all__ = [
    "FiefAuth",
    "FiefAuthError",
    "FiefAuthUnauthorized",
    "FiefAuthForbidden",
    "TokenGetter",
    "get_authorization_scheme_token",
    "get_cookie",
]
