import uuid
from functools import wraps
from typing import Callable, List, Optional

from flask import g, request

from fief_client import (
    Fief,
    FiefAccessTokenExpired,
    FiefAccessTokenInfo,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingScope,
    FiefUserInfo,
)
from fief_client.client import FiefAccessTokenMissingPermission


class FiefAuthError(Exception):
    pass


class FiefAuthUnauthorized(FiefAuthError):
    pass


class FiefAuthForbidden(FiefAuthError):
    pass


TokenGetter = Callable[[], Optional[str]]
UserInfoCacheGetter = Callable[[uuid.UUID], Optional[FiefUserInfo]]
UserInfoCacheSetter = Callable[[uuid.UUID, FiefUserInfo], None]


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
    def __init__(
        self,
        client: Fief,
        token_getter: TokenGetter,
        *,
        get_userinfo_cache: Optional[UserInfoCacheGetter] = None,
        set_userinfo_cache: Optional[UserInfoCacheSetter] = None,
    ) -> None:
        self.client = client
        self.token_getter = token_getter
        self.get_userinfo_cache = get_userinfo_cache
        self.set_userinfo_cache = set_userinfo_cache

    def authenticated(
        self,
        *,
        scope: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
    ):
        def _authenticated(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = self.token_getter()
                if token is None:
                    raise FiefAuthUnauthorized()

                try:
                    info = self.client.validate_access_token(
                        token, required_scope=scope, required_permissions=permissions
                    )
                except (FiefAccessTokenInvalid, FiefAccessTokenExpired) as e:
                    raise FiefAuthUnauthorized() from e
                except (
                    FiefAccessTokenMissingScope,
                    FiefAccessTokenMissingPermission,
                ) as e:
                    raise FiefAuthForbidden() from e

                g.access_token_info = info

                return f(*args, **kwargs)

            return decorated_function

        return _authenticated

    def current_user(
        self,
        *,
        scope: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        refresh: bool = False,
    ):
        def _current_user(f):
            @wraps(f)
            @self.authenticated(scope=scope, permissions=permissions)
            def decorated_function(*args, **kwargs):
                access_token_info: FiefAccessTokenInfo = g.access_token_info

                userinfo = None
                if self.get_userinfo_cache is not None:
                    userinfo = self.get_userinfo_cache(access_token_info["id"])

                if userinfo is None or refresh:
                    userinfo = self.client.userinfo(access_token_info["access_token"])

                    if self.set_userinfo_cache is not None:
                        self.set_userinfo_cache(access_token_info["id"], userinfo)

                g.user = userinfo

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
