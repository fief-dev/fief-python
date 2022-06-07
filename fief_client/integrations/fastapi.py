import sys
import uuid
from inspect import Parameter, Signature, isawaitable
from typing import (
    AsyncGenerator,
    Callable,
    Coroutine,
    Generator,
    List,
    Optional,
    TypeVar,
    Union,
    cast,
)

if sys.version_info < (3, 8):
    from typing_extensions import Protocol  # pragma: no cover
else:
    from typing import Protocol  # pragma: no cover

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security.base import SecurityBase
from fastapi.security.http import HTTPAuthorizationCredentials
from makefun import with_signature

from fief_client import (
    Fief,
    FiefAccessTokenExpired,
    FiefAccessTokenInfo,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingPermission,
    FiefAccessTokenMissingScope,
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
    async def get(self, user_id: uuid.UUID) -> Optional[FiefUserInfo]:
        ...  # pragma: no cover

    async def set(self, user_id: uuid.UUID, userinfo: FiefUserInfo) -> None:
        ...  # pragma: no cover


class FiefAuth:
    def __init__(
        self,
        client: FiefClientClass,
        scheme: SecurityBase,
        *,
        get_userinfo_cache: Optional[DependencyCallable[UserInfoCacheProtocol]] = None
    ) -> None:
        self.client = client
        self.scheme = scheme
        self.get_userinfo_cache = get_userinfo_cache

    def authenticated(
        self, scope: Optional[List[str]] = None, permissions: Optional[List[str]] = None
    ):
        signature = self._get_authenticated_call_signature(self.scheme)

        @with_signature(signature)
        async def _authenticated(
            request: Request, response: Response, token: Optional[TokenType]
        ) -> FiefAccessTokenInfo:
            if token is None:
                return await self.get_unauthorized_response(request, response)

            if isinstance(token, HTTPAuthorizationCredentials):
                token = token.credentials

            try:
                result = self.client.validate_access_token(
                    token, required_scope=scope, required_permissions=permissions
                )
                if isawaitable(result):
                    info = await result
                else:
                    info = result
            except (FiefAccessTokenInvalid, FiefAccessTokenExpired):
                return await self.get_unauthorized_response(request, response)
            except (FiefAccessTokenMissingScope, FiefAccessTokenMissingPermission):
                return await self.get_forbidden_response(request, response)

            return info

        return _authenticated

    def current_user(
        self,
        scope: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        refresh: bool = False,
    ):
        signature = self._get_current_user_call_signature(
            self.authenticated(scope, permissions)
        )

        @with_signature(signature)
        async def _current_user(
            access_token_info: FiefAccessTokenInfo, *args, **kwargs
        ) -> FiefUserInfo:
            userinfo_cache: Optional[UserInfoCacheProtocol] = kwargs.get(
                "userinfo_cache"
            )

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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    async def get_forbidden_response(self, request: Request, response: Response):
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


__all__ = ["FiefAuth", "FiefClientClass"]
