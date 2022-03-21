from inspect import Parameter, Signature, isawaitable
from typing import Callable, List, Optional, Union, cast

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security.base import SecurityBase
from fastapi.security.http import HTTPAuthorizationCredentials
from makefun import with_signature

from fief_client import (
    Fief,
    FiefAccessTokenExpired,
    FiefAccessTokenInfo,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingScope,
    FiefAsync,
)

FiefClientClass = Union[Fief, FiefAsync]

TokenType = Union[str, HTTPAuthorizationCredentials]


class FiefAuth:
    def __init__(self, client: FiefClientClass, scheme: SecurityBase) -> None:
        self.client = client
        self.scheme = scheme

    def current_user(self, scope: Optional[List[str]] = None):
        signature = self._get_call_signature(self.scheme)

        @with_signature(signature)
        async def _current_user(
            request: Request, response: Response, token: Optional[TokenType]
        ) -> FiefAccessTokenInfo:
            if token is None:
                return await self.get_unauthorized_response(request, response)

            if isinstance(token, HTTPAuthorizationCredentials):
                token = token.credentials

            try:
                result = self.client.validate_access_token(token, required_scope=scope)
                if isawaitable(result):
                    info = await result
                else:
                    info = result
            except (FiefAccessTokenInvalid, FiefAccessTokenExpired):
                return await self.get_unauthorized_response(request, response)
            except FiefAccessTokenMissingScope:
                return await self.get_forbidden_response(request, response)

            return info

        return _current_user

    async def get_unauthorized_response(self, request: Request, response: Response):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    async def get_forbidden_response(self, request: Request, response: Response):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    def _get_call_signature(self, scheme: SecurityBase) -> Signature:
        """
        Generate a dynamic signature for the __call__ dependency.
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


__all__ = ["FiefAuth", "FiefClientClass"]
