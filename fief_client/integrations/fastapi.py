import uuid
from inspect import Parameter, Signature, isawaitable
from typing import Callable, List, Optional, Union, cast

from fastapi import Depends, HTTPException, status
from fastapi.security.base import SecurityBase
from fastapi.security.http import HTTPAuthorizationCredentials
from makefun import with_signature

from fief_client import (
    Fief,
    FiefAccessTokenExpired,
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
        async def _current_user(token: Optional[TokenType]) -> uuid.UUID:
            if token is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

            if isinstance(token, HTTPAuthorizationCredentials):
                token = token.credentials

            try:
                result = self.client.validate_access_token(token, required_scope=scope)
                if isawaitable(result):
                    user_id = await result
                else:
                    user_id = result
            except (FiefAccessTokenInvalid, FiefAccessTokenExpired) as e:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from e
            except FiefAccessTokenMissingScope as e:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN) from e

            return uuid.UUID(user_id)

        return _current_user

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
                name="token",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                default=Depends(cast(Callable, scheme)),
            )
        ]

        return Signature(parameters)


__all__ = ["FiefAuth", "FiefClientClass"]
