import sys

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict

import contextlib
import json
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlencode

import httpx
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException

HTTPXClient = Union[httpx.Client, httpx.AsyncClient]


class FiefTokenResponse(TypedDict):
    access_token: str
    id_token: str
    token_type: str


class FiefError(Exception):
    pass


class FiefIdTokenInvalidError(FiefError):
    pass


class BaseFief:
    base_url: str
    client_id: str
    client_secret: str
    encryption_key: Optional[jwk.JWK] = None

    _openid_configuration: Optional[Dict[str, Any]] = None
    _jwks: Optional[jwk.JWKSet] = None

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        encryption_key: Optional[str] = None,
    ) -> None:
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        if encryption_key is not None:
            self.encryption_key = jwk.JWK.from_json(encryption_key)

    def _auth_url(
        self,
        openid_configuration: Dict[str, Any],
        redirect_uri: str,
        *,
        state: str = None,
        scope: Optional[List[str]] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
        }

        if state is not None:
            params["state"] = state

        if scope is not None:
            params["scope"] = " ".join(scope)

        if extras_params is not None:
            params = {**params, **extras_params}

        authorization_endpoint = openid_configuration["authorization_endpoint"]
        return f"{authorization_endpoint}?{urlencode(params)}"

    def _decode_id_token(self, id_token: str, jwks: jwk.JWKSet) -> Dict[str, Any]:
        try:
            if self.encryption_key is not None:
                decrypted_id_token = jwt.JWT(jwt=id_token, key=self.encryption_key)
                id_token_claims = decrypted_id_token.claims
            else:
                id_token_claims = id_token

            signed_id_token = jwt.JWT(jwt=id_token_claims, algs=["RS256"], key=jwks)
            return json.loads(signed_id_token.claims)
        except JWException as e:
            raise FiefIdTokenInvalidError() from e

    def _get_openid_configuration_request(self, client: HTTPXClient) -> httpx.Request:
        return client.build_request("GET", "/.well-known/openid-configuration")

    def _get_auth_exchange_token_request(
        self, client: HTTPXClient, *, endpoint: str, code: str, redirect_uri: str
    ) -> httpx.Request:
        return client.build_request(
            "POST",
            endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )


class Fief(BaseFief):
    def auth_url(
        self,
        redirect_uri: str,
        *,
        state: str = None,
        scope: Optional[List[str]] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        openid_configuration = self._get_openid_configuration()
        return self._auth_url(
            openid_configuration,
            redirect_uri,
            state=state,
            scope=scope,
            extras_params=extras_params,
        )

    def auth_callback(
        self, code: str, redirect_uri: str
    ) -> Tuple[FiefTokenResponse, Dict[str, Any]]:
        token_response = self._auth_exchange_token(code, redirect_uri)
        jwks = self._get_jwks()
        userinfo = self._decode_id_token(token_response["id_token"], jwks)
        return token_response, userinfo

    @contextlib.contextmanager
    def _get_httpx_client(self):
        with httpx.Client(base_url=self.base_url) as client:
            yield client

    def _get_openid_configuration(self) -> Dict[str, Any]:
        if self._openid_configuration is not None:
            return self._openid_configuration

        with self._get_httpx_client() as client:
            request = self._get_openid_configuration_request(client)
            response = client.send(request)
            json = response.json()
            self._openid_configuration = json
            return json

    def _get_jwks(self) -> jwk.JWKSet:
        if self._jwks is not None:
            return self._jwks

        jwks_uri = self._get_openid_configuration()["jwks_uri"]
        with self._get_httpx_client() as client:
            response = client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    def _auth_exchange_token(self, code: str, redirect_uri) -> FiefTokenResponse:
        token_endpoint = self._get_openid_configuration()["token_endpoint"]
        with self._get_httpx_client() as client:
            request = self._get_auth_exchange_token_request(
                client,
                endpoint=token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
            )
            response = client.send(request)

            response.raise_for_status()

            return response.json()


class FiefAsync(BaseFief):
    async def auth_url(
        self,
        redirect_uri: str,
        *,
        state: str = None,
        scope: Optional[List[str]] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        openid_configuration = await self._get_openid_configuration()
        return self._auth_url(
            openid_configuration,
            redirect_uri,
            state=state,
            scope=scope,
            extras_params=extras_params,
        )

    async def auth_callback(
        self, code: str, redirect_uri: str
    ) -> Tuple[FiefTokenResponse, Dict[str, Any]]:
        token_response = await self._auth_exchange_token(code, redirect_uri)
        jwks = await self._get_jwks()
        userinfo = self._decode_id_token(token_response["id_token"], jwks)
        return token_response, userinfo

    @contextlib.asynccontextmanager
    async def _get_httpx_client(self):
        async with httpx.AsyncClient(base_url=self.base_url) as client:
            yield client

    async def _get_openid_configuration(self) -> Dict[str, Any]:
        if self._openid_configuration is not None:
            return self._openid_configuration

        async with self._get_httpx_client() as client:
            request = self._get_openid_configuration_request(client)
            response = await client.send(request)
            json = response.json()
            self._openid_configuration = json
            return json

    async def _get_jwks(self) -> jwk.JWKSet:
        if self._jwks is not None:
            return self._jwks

        jwks_uri = (await self._get_openid_configuration())["jwks_uri"]
        async with self._get_httpx_client() as client:
            response = await client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    async def _auth_exchange_token(self, code: str, redirect_uri) -> FiefTokenResponse:
        token_endpoint = (await self._get_openid_configuration())["token_endpoint"]
        async with self._get_httpx_client() as client:
            request = self._get_auth_exchange_token_request(
                client,
                endpoint=token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
            )
            response = await client.send(request)

            response.raise_for_status()

            return response.json()
