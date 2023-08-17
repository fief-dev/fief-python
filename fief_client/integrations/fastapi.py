"""FastAPI integration."""
import uuid
from inspect import Parameter, Signature, isawaitable
from typing import (
    AsyncGenerator,
    Callable,
    Coroutine,
    Generator,
    List,
    Optional,
    Protocol,
    TypeVar,
    Union,
    cast,
)

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security.base import SecurityBase
from fastapi.security.http import HTTPAuthorizationCredentials
from makefun import with_signature

from fief_client import (
    Fief,
    FiefAccessTokenACRTooLow,
    FiefAccessTokenExpired,
    FiefAccessTokenInfo,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingPermission,
    FiefAccessTokenMissingScope,
    FiefACR,
    FiefAsync,
    FiefUserInfo,
)

FiefClientClass = Union[Fief, FiefAsync]

TokenType = Union[str, HTTPAuthorizationCredentials]

RETURN_TYPE = TypeVar("RETURN_TYPE")

DependencyCallable = Callable[
    ...,
    Union[
        RETURN_TYPE,
        Coroutine[None, None, RETURN_TYPE],
        AsyncGenerator[RETURN_TYPE, None],
        Generator[RETURN_TYPE, None, None],
    ],
]


class UserInfoCacheProtocol(Protocol):
    """
    Protocol that should follow a class to implement a cache mechanism for user information.

    Read more: https://docs.fief.dev/integrate/python/fastapi/#caching-user-information
    """

    async def get(self, user_id: uuid.UUID) -> Optional[FiefUserInfo]:
        """
        Retrieve user information from cache, if available.

        :param user_id: The ID of the user to retrieve information for.
        """
        ...  # pragma: no cover

    async def set(self, user_id: uuid.UUID, userinfo: FiefUserInfo) -> None:
        """
        Store user information in cache.

        :param user_id: The ID of the user to cache information for.
        :param userinfo: The user information to cache.
        """
        ...  # pragma: no cover


class FiefAuth:
    """
    Helper class to integrate Fief authentication with FastAPI.

    **Example:**

    ```py
    from fastapi.security import OAuth2AuthorizationCodeBearer
    from fief_client import FiefAccessTokenInfo, FiefAsync
    from fief_client.integrations.fastapi import FiefAuth

    fief = FiefAsync(
        "https://example.fief.dev",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )

    scheme = OAuth2AuthorizationCodeBearer(
        "https://example.fief.dev/authorize",
        "https://example.fief.dev/api/token",
        scopes={"openid": "openid", "offline_access": "offline_access"},
    )

    auth = FiefAuth(fief, scheme)
    ```
    """

    def __init__(
        self,
        client: FiefClientClass,
        scheme: SecurityBase,
        *,
        get_userinfo_cache: Optional[DependencyCallable[UserInfoCacheProtocol]] = None,
    ) -> None:
        """
        :param client: Instance of a Fief client.
        Can be either `fief_client.Fief` or `fief_client.FiefAsync`.
        :param scheme: FastAPI security scheme.
        It'll be used to retrieve the access token in the request.
        :param get_userinfo_cache: Optional dependency returning an instance of a class
        following the `UserInfoCacheProtocol`.
        It'll be used to cache user information on your server.
        Otherwise, the Fief API will always be reached when requesting user information.
        """
        self.client = client
        self.scheme = scheme
        self.get_userinfo_cache = get_userinfo_cache

    def authenticated(
        self,
        optional: bool = False,
        scope: Optional[List[str]] = None,
        acr: Optional[FiefACR] = None,
        permissions: Optional[List[str]] = None,
    ):
        """
        Return a FastAPI dependency to check if a request is authenticated.

        If the request is authenticated, the dependency will return a `fief_client.FiefAccessTokenInfo`.

        :param optional: If `False` and the request is not authenticated,
        an unauthorized response will be raised.
        :param scope: Optional list of scopes required.
        If the access token lacks one of the required scope, a forbidden response will be raised.
        :param acr: Optional minimum ACR level required.
        If the access token doesn't meet the minimum level, a forbidden response will be raised.
        Read more: https://docs.fief.dev/going-further/acr/
        :param permissions: Optional list of permissions required.
        If the access token lacks one of the required permission, a forbidden response will be raised.

        **Example**

        ```py
        @app.get("/authenticated")
        async def get_authenticated(
            access_token_info: FiefAccessTokenInfo = Depends(auth.authenticated()),
        ):
            return access_token_info
        ```
        """
        signature = self._get_authenticated_call_signature(self.scheme)

        @with_signature(signature)
        async def _authenticated(
            request: Request, response: Response, token: Optional[TokenType]
        ) -> Optional[FiefAccessTokenInfo]:
            if token is None:
                if optional:
                    return None
                return await self.get_unauthorized_response(request, response)

            if isinstance(token, HTTPAuthorizationCredentials):
                token = token.credentials

            try:
                result = self.client.validate_access_token(
                    token,
                    required_scope=scope,
                    required_acr=acr,
                    required_permissions=permissions,
                )
                if isawaitable(result):
                    info = await result
                else:
                    info = result
            except (FiefAccessTokenInvalid, FiefAccessTokenExpired):
                if optional:
                    return None
                return await self.get_unauthorized_response(request, response)
            except (
                FiefAccessTokenMissingScope,
                FiefAccessTokenACRTooLow,
                FiefAccessTokenMissingPermission,
            ):
                return await self.get_forbidden_response(request, response)

            return info

        return _authenticated

    def current_user(
        self,
        optional: bool = False,
        scope: Optional[List[str]] = None,
        acr: Optional[FiefACR] = None,
        permissions: Optional[List[str]] = None,
        refresh: bool = False,
    ):
        """
        Return a FastAPI dependency to check if a user is authenticated.

        If the request is authenticated, the dependency will return a `fief_client.FiefUserInfo`.

        If provided, the cache mechanism will be used to retrieve this information without calling the Fief API.

        :param optional: If `False` and the request is not authenticated,
        an unauthorized response will be raised.
        :param scope: Optional list of scopes required.
        If the access token lacks one of the required scope, a forbidden response will be raised.
        :param acr: Optional minimum ACR level required.
        If the access token doesn't meet the minimum level, a forbidden response will be raised.
        Read more: https://docs.fief.dev/going-further/acr/
        :param permissions: Optional list of permissions required.
        If the access token lacks one of the required permission, a forbidden response will be raised.
        :param refresh: If `True`, the user information will be refreshed from the Fief API.
        Otherwise, the cache will be used.

        **Example**

        ```py
        @app.get("/current-user", name="current_user")
        async def get_current_user(
            user: FiefUserInfo = Depends(auth.current_user()),
        ):
            return {"email": user["email"]}
        ```
        """
        signature = self._get_current_user_call_signature(
            self.authenticated(optional, scope, acr, permissions)
        )

        @with_signature(signature)
        async def _current_user(
            access_token_info: Optional[FiefAccessTokenInfo], *args, **kwargs
        ) -> Optional[FiefUserInfo]:
            userinfo_cache: Optional[UserInfoCacheProtocol] = kwargs.get(
                "userinfo_cache"
            )

            if access_token_info is None and optional:
                return None
            assert access_token_info is not None

            userinfo = None
            if userinfo_cache is not None:
                userinfo = await userinfo_cache.get(access_token_info["id"])

            if userinfo is None or refresh:
                result = self.client.userinfo(access_token_info["access_token"])
                if isawaitable(result):
                    userinfo = cast(FiefUserInfo, await result)
                else:
                    userinfo = cast(FiefUserInfo, result)

                if userinfo_cache is not None:
                    await userinfo_cache.set(access_token_info["id"], userinfo)

            return userinfo

        return _current_user

    async def get_unauthorized_response(self, request: Request, response: Response):
        """
        Raise an `fastapi.HTTPException` with the status code 401.

        This method is called when using the `authenticated` or `current_user` dependency
        but the request is not authenticated.

        You can override this method to customize the behavior in this case.
        """
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    async def get_forbidden_response(self, request: Request, response: Response):
        """
        Raise an `fastapi.HTTPException` with the status code 403.

        This method is called when using the `authenticated` or `current_user` dependency
        but the access token doesn't match the list of scopes or permissions.

        You can override this method to customize the behavior in this case.
        """
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    def _get_authenticated_call_signature(self, scheme: SecurityBase) -> Signature:
        """
        Generate a dynamic signature for the authenticated dependency.
        Here comes some blood magic 🧙‍♂️
        Thank to "makefun", we are able to generate callable
        with a dynamic security scheme dependency at runtime.
        This way, it's detected by the OpenAPI generator.
        """
        parameters: List[Parameter] = [
            Parameter(
                name="request",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Request,
            ),
            Parameter(
                name="response",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Response,
            ),
            Parameter(
                name="token",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                default=Depends(cast(Callable, scheme)),
            ),
        ]

        return Signature(parameters)

    def _get_current_user_call_signature(self, authenticated: Callable) -> Signature:
        """
        Generate a dynamic signature for the current_user dependency.
        Here comes some blood magic 🧙‍♂️
        Thank to "makefun", we are able to generate callable
        with a dynamic security scheme dependency at runtime.
        This way, it's detected by the OpenAPI generator.
        """
        parameters: List[Parameter] = [
            Parameter(
                name="access_token_info",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                default=Depends(authenticated),
                annotation=FiefAccessTokenInfo,
            ),
        ]

        if self.get_userinfo_cache is not None:
            parameters.append(
                Parameter(
                    name="userinfo_cache",
                    kind=Parameter.POSITIONAL_OR_KEYWORD,
                    default=Depends(self.get_userinfo_cache),
                    annotation=UserInfoCacheProtocol,
                ),
            )

        return Signature(parameters)


__all__ = ["FiefAuth", "FiefClientClass", "UserInfoCacheProtocol"]
