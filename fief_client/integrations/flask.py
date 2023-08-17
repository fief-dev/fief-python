"""Flask integration."""
import uuid
from functools import wraps
from typing import Callable, List, Optional

from flask import g, request

from fief_client import (
    Fief,
    FiefAccessTokenACRTooLow,
    FiefAccessTokenExpired,
    FiefAccessTokenInfo,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingScope,
    FiefACR,
    FiefUserInfo,
)
from fief_client.client import FiefAccessTokenMissingPermission


class FiefAuthError(Exception):
    """
    Base error for FiefAuth integration.
    """


class FiefAuthUnauthorized(FiefAuthError):
    """
    Request unauthorized error.

    This error is raised when using the `authenticated` or `current_user` decorator
    but the request is not authenticated.

    You should implement an `errorhandler` to define the behavior of your server when
    this happens.

    **Example:**

    ```py
    @app.errorhandler(FiefAuthUnauthorized)
    def fief_unauthorized_error(e):
        return "", 401
    ```
    """


class FiefAuthForbidden(FiefAuthError):
    """
    Request forbidden error.

    This error is raised when using the `authenticated` or `current_user` decorator
    but the access token doesn't match the list of scopes, permissions or minimum ACR level.

    You should implement an `errorhandler` to define the behavior of your server when
    this happens.

    **Example:**

    ```py
    @app.errorhandler(FiefAuthForbidden)
    def fief_forbidden_error(e):
        return "", 403
    ```
    """


TokenGetter = Callable[[], Optional[str]]
"""Type of a function that can be used to retrieve a token."""

UserInfoCacheGetter = Callable[[uuid.UUID], Optional[FiefUserInfo]]
"""
Type of a function that can be used to retrieve user information from a cache.

Read more: https://docs.fief.dev/integrate/python/flask/#web-application-example
"""

UserInfoCacheSetter = Callable[[uuid.UUID, FiefUserInfo], None]
"""
Type of a function that can be used to store user information in a cache.

Read more: https://docs.fief.dev/integrate/python/flask/#web-application-example
"""


def get_authorization_scheme_token(*, scheme: str = "bearer") -> TokenGetter:
    """
    Return a `TokenGetter` function to retrieve a token from the `Authorization` header of an HTTP request.

    :param scheme: Scheme of the token. Defaults to `bearer`.
    """

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
    """
    Return a `TokenGetter` function to retrieve a token from a `Cookie` of an HTTP request.

    :param cookie_name: Name of the cookie.
    """

    def _get_cookie():
        return request.cookies.get(cookie_name)

    return _get_cookie


class FiefAuth:
    """
    Helper class to integrate Fief authentication with Flask.

    **Example:**

    ```py
    from fief_client import Fief
    from fief_client.integrations.flask import (
        FiefAuth,
        get_authorization_scheme_token,
    )
    from flask import Flask, g

    fief = Fief(
        "https://example.fief.dev",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )

    auth = FiefAuth(fief, get_authorization_scheme_token())

    app = Flask(__name__)
    ```
    """

    def __init__(
        self,
        client: Fief,
        token_getter: TokenGetter,
        *,
        get_userinfo_cache: Optional[UserInfoCacheGetter] = None,
        set_userinfo_cache: Optional[UserInfoCacheSetter] = None,
    ) -> None:
        """
        :param client: Instance of a `fief_client.Fief` client.
        :param token_getter: Function to retrieve a token.
        It should follow the `TokenGetter` type.
        :param get_userinfo_cache: Optional function to retrieve user information from a cache.
        Otherwise, the Fief API will always be reached when requesting user information.
        It should follow the `UserInfoCacheGetter` type.
        :param set_userinfo_cache: Optional function to store user information in a cache.
        It should follow the `UserInfoCacheSetter` type.
        """
        self.client = client
        self.token_getter = token_getter
        self.get_userinfo_cache = get_userinfo_cache
        self.set_userinfo_cache = set_userinfo_cache

    def authenticated(
        self,
        *,
        optional: bool = False,
        scope: Optional[List[str]] = None,
        acr: Optional[FiefACR] = None,
        permissions: Optional[List[str]] = None,
    ):
        """
        Decorator to check if a request is authenticated.

        If the request is authenticated, the `g` object will have an `access_token_info` property,
        of type `fief_client.FiefAccessTokenInfo`.

        :param optional: If `False` and the request is not authenticated,
        a `FiefAuthUnauthorized` error will be raised.
        :param scope: Optional list of scopes required.
        If the access token lacks one of the required scope, a `FiefAuthForbidden` error will be raised.
        :param acr: Optional minimum ACR level required.
        If the access token doesn't meet the minimum level, a `FiefAuthForbidden` error will be raised.
        Read more: https://docs.fief.dev/going-further/acr/
        :param permissions: Optional list of permissions required.
        If the access token lacks one of the required permission, a `FiefAuthForbidden` error will be raised.

        **Example**

        ```py
        @app.get("/authenticated")
        @auth.authenticated()
        def get_authenticated():
            return g.access_token_info
        ```
        """

        def _authenticated(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = self.token_getter()
                if token is None:
                    if optional:
                        g.access_token_info = None
                        return f(*args, **kwargs)
                    raise FiefAuthUnauthorized()

                try:
                    info = self.client.validate_access_token(
                        token,
                        required_scope=scope,
                        required_acr=acr,
                        required_permissions=permissions,
                    )
                except (FiefAccessTokenInvalid, FiefAccessTokenExpired) as e:
                    if optional:
                        g.access_token_info = None
                        return f(*args, **kwargs)
                    raise FiefAuthUnauthorized() from e
                except (
                    FiefAccessTokenMissingScope,
                    FiefAccessTokenACRTooLow,
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
        optional: bool = False,
        scope: Optional[List[str]] = None,
        acr: Optional[FiefACR] = None,
        permissions: Optional[List[str]] = None,
        refresh: bool = False,
    ):
        """
        Decorator to check if a user is authenticated.

        If the request is authenticated, the `g` object will have a `user` property,
        of type `fief_client.FiefUserInfo`.

        :param optional: If `False` and the request is not authenticated,
        a `FiefAuthUnauthorized` error will be raised.
        :param scope: Optional list of scopes required.
        If the access token lacks one of the required scope, a `FiefAuthForbidden` error will be raised.
        :param acr: Optional minimum ACR level required.
        If the access token doesn't meet the minimum level, a `FiefAuthForbidden` error will be raised.
        Read more: https://docs.fief.dev/going-further/acr/
        :param permissions: Optional list of permissions required.
        If the access token lacks one of the required permission, a `FiefAuthForbidden` error will be raised.
        :param refresh: If `True`, the user information will be refreshed from the Fief API.
        Otherwise, the cache will be used.

        **Example**

        ```py
        @app.get("/current-user")
        @auth.current_user()
        def get_current_user():
            user = g.user
            return f"<h1>You are authenticated. Your user email is {user['email']}</h1>"
        ```
        """

        def _current_user(f):
            @wraps(f)
            @self.authenticated(
                optional=optional, scope=scope, acr=acr, permissions=permissions
            )
            def decorated_function(*args, **kwargs):
                access_token_info: Optional[FiefAccessTokenInfo] = g.access_token_info

                if access_token_info is None and optional:
                    g.user = None
                    return f(*args, **kwargs)

                assert access_token_info is not None

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
    "UserInfoCacheGetter",
    "UserInfoCacheSetter",
    "get_authorization_scheme_token",
    "get_cookie",
]
