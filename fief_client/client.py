import sys
import uuid

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict  # pragma: no cover
else:
    from typing import TypedDict  # pragma: no cover

import contextlib
import json
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlencode

import httpx
from jwcrypto import jwk, jwt

from fief_client.crypto import is_valid_hash

HTTPXClient = Union[httpx.Client, httpx.AsyncClient]


class FiefTokenResponse(TypedDict):
    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str]


class FiefAccessTokenInfo(TypedDict):
    id: uuid.UUID
    scope: List[str]
    permissions: List[str]
    access_token: str


FiefUserInfo = Dict[str, Any]


class FiefError(Exception):
    pass


class FiefAccessTokenInvalid(FiefError):
    pass


class FiefAccessTokenExpired(FiefError):
    pass


class FiefAccessTokenMissingScope(FiefError):
    pass


class FiefAccessTokenMissingPermission(FiefError):
    pass


class FiefIdTokenInvalid(FiefError):
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
        host: Optional[str] = None,
    ) -> None:
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        if encryption_key is not None:
            self.encryption_key = jwk.JWK.from_json(encryption_key)
        self.host = host

    def _get_endpoint_url(
        self, openid_configuration: Dict[str, Any], field: str
    ) -> str:
        return openid_configuration[field]

    def _auth_url(
        self,
        openid_configuration: Dict[str, Any],
        redirect_uri: str,
        *,
        state: str = None,
        scope: Optional[List[str]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
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

        if code_challenge is not None and code_challenge_method is not None:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        if extras_params is not None:
            params = {**params, **extras_params}

        authorization_endpoint = self._get_endpoint_url(
            openid_configuration, "authorization_endpoint"
        )
        return f"{authorization_endpoint}?{urlencode(params)}"

    def _validate_access_token(
        self,
        access_token: str,
        jwks: jwk.JWKSet,
        *,
        required_scope: Optional[List[str]] = None,
        required_permissions: Optional[List[str]] = None,
    ) -> FiefAccessTokenInfo:
        try:
            decoded_token = jwt.JWT(jwt=access_token, algs=["RS256"], key=jwks)
            claims = json.loads(decoded_token.claims)
            access_token_scope = claims["scope"].split()
            if required_scope is not None:
                for scope in required_scope:
                    if scope not in access_token_scope:
                        raise FiefAccessTokenMissingScope()

            permissions: List[str] = claims["permissions"]
            if required_permissions is not None:
                for required_permission in required_permissions:
                    if required_permission not in permissions:
                        raise FiefAccessTokenMissingPermission()

            return {
                "id": uuid.UUID(claims["sub"]),
                "scope": access_token_scope,
                "permissions": permissions,
                "access_token": access_token,
            }

        except jwt.JWTExpired as e:
            raise FiefAccessTokenExpired() from e
        except jwt.JWException as e:
            raise FiefAccessTokenInvalid() from e
        except KeyError as e:
            raise FiefAccessTokenInvalid() from e

    def _decode_id_token(
        self,
        id_token: str,
        jwks: jwk.JWKSet,
        *,
        code: Optional[str] = None,
        access_token: Optional[str] = None,
    ) -> FiefUserInfo:
        try:
            if self.encryption_key is not None:
                decrypted_id_token = jwt.JWT(jwt=id_token, key=self.encryption_key)
                id_token_claims = decrypted_id_token.claims
            else:
                id_token_claims = id_token

            signed_id_token = jwt.JWT(jwt=id_token_claims, algs=["RS256"], key=jwks)
            claims = json.loads(signed_id_token.claims)

            if "c_hash" in claims:
                if code is None or not is_valid_hash(code, claims["c_hash"]):
                    raise FiefIdTokenInvalid()

            if "at_hash" in claims:
                if access_token is None or not is_valid_hash(
                    access_token, claims["at_hash"]
                ):
                    raise FiefIdTokenInvalid()

            return claims
        except jwt.JWException as e:
            raise FiefIdTokenInvalid() from e

    def _get_openid_configuration_request(self, client: HTTPXClient) -> httpx.Request:
        return client.build_request("GET", "/.well-known/openid-configuration")

    def _get_auth_exchange_token_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> httpx.Request:
        basic_auth = httpx.BasicAuth(self.client_id, self.client_secret)
        return client.build_request(
            "POST",
            endpoint,
            headers={
                "Authorization": basic_auth._auth_header,
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )

    def _get_auth_refresh_token_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        refresh_token: str,
        scope: Optional[List[str]] = None,
    ) -> httpx.Request:
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if scope is not None:
            data["scope"] = " ".join(scope)

        basic_auth = httpx.BasicAuth(self.client_id, self.client_secret)
        return client.build_request(
            "POST",
            endpoint,
            headers={
                "Authorization": basic_auth._auth_header,
            },
            data=data,
        )

    def _get_userinfo_request(
        self, client: HTTPXClient, *, endpoint: str, access_token: str
    ) -> httpx.Request:
        return client.build_request(
            "GET", endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )

    def _get_update_profile_request(
        self,
        client: HTTPXClient,
        *,
        endpoint: str,
        access_token: str,
        data: Dict[str, Any],
    ) -> httpx.Request:
        return client.build_request(
            "PATCH",
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            json=data,
        )


class Fief(BaseFief):
    def auth_url(
        self,
        redirect_uri: str,
        *,
        state: str = None,
        scope: Optional[List[str]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        openid_configuration = self._get_openid_configuration()
        return self._auth_url(
            openid_configuration,
            redirect_uri,
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            extras_params=extras_params,
        )

    def auth_callback(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        token_response = self._auth_exchange_token(
            code, redirect_uri, code_verifier=code_verifier
        )
        jwks = self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            code=code,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    def auth_refresh_token(
        self, refresh_token: str, *, scope: Optional[List[str]] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        token_endpoint = self._get_endpoint_url(
            self._get_openid_configuration(), "token_endpoint"
        )
        with self._get_httpx_client() as client:
            request = self._get_auth_refresh_token_request(
                client,
                endpoint=token_endpoint,
                refresh_token=refresh_token,
                scope=scope,
            )
            response = client.send(request)

            response.raise_for_status()

            token_response = response.json()
        jwks = self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    def validate_access_token(
        self,
        access_token: str,
        *,
        required_scope: Optional[List[str]] = None,
        required_permissions: Optional[List[str]] = None,
    ) -> FiefAccessTokenInfo:
        jwks = self._get_jwks()
        return self._validate_access_token(
            access_token,
            jwks,
            required_scope=required_scope,
            required_permissions=required_permissions,
        )

    def userinfo(self, access_token: str) -> FiefUserInfo:
        userinfo_endpoint = self._get_endpoint_url(
            self._get_openid_configuration(), "userinfo_endpoint"
        )
        with self._get_httpx_client() as client:
            request = self._get_userinfo_request(
                client, endpoint=userinfo_endpoint, access_token=access_token
            )
            response = client.send(request)

            response.raise_for_status()

            return response.json()

    def update_profile(self, access_token: str, data: Dict[str, Any]) -> FiefUserInfo:
        update_profile_endpoint = f"{self.base_url}/api/profile"

        with self._get_httpx_client() as client:
            request = self._get_update_profile_request(
                client,
                endpoint=update_profile_endpoint,
                access_token=access_token,
                data=data,
            )
            response = client.send(request)

            response.raise_for_status()

            return response.json()

    def logout_url(self, redirect_uri: str) -> str:
        params = {"redirect_uri": redirect_uri}
        return f"{self.base_url}/logout?{urlencode(params)}"

    @contextlib.contextmanager
    def _get_httpx_client(self):
        headers = {}
        if self.host is not None:
            headers["Host"] = self.host

        with httpx.Client(base_url=self.base_url, headers=headers) as client:
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

        jwks_uri = self._get_endpoint_url(self._get_openid_configuration(), "jwks_uri")
        with self._get_httpx_client() as client:
            response = client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    def _auth_exchange_token(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> FiefTokenResponse:
        token_endpoint = self._get_endpoint_url(
            self._get_openid_configuration(), "token_endpoint"
        )
        with self._get_httpx_client() as client:
            request = self._get_auth_exchange_token_request(
                client,
                endpoint=token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
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
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        extras_params: Optional[Mapping[str, str]] = None,
    ) -> str:
        openid_configuration = await self._get_openid_configuration()
        return self._auth_url(
            openid_configuration,
            redirect_uri,
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            extras_params=extras_params,
        )

    async def auth_callback(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        token_response = await self._auth_exchange_token(
            code, redirect_uri, code_verifier=code_verifier
        )
        jwks = await self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            code=code,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    async def auth_refresh_token(
        self, refresh_token: str, *, scope: Optional[List[str]] = None
    ) -> Tuple[FiefTokenResponse, FiefUserInfo]:
        token_endpoint = self._get_endpoint_url(
            await self._get_openid_configuration(), "token_endpoint"
        )
        async with self._get_httpx_client() as client:
            request = self._get_auth_refresh_token_request(
                client,
                endpoint=token_endpoint,
                refresh_token=refresh_token,
                scope=scope,
            )
            response = await client.send(request)

            response.raise_for_status()

            token_response = response.json()

        jwks = await self._get_jwks()
        userinfo = self._decode_id_token(
            token_response["id_token"],
            jwks,
            access_token=token_response.get("access_token"),
        )
        return token_response, userinfo

    async def validate_access_token(
        self,
        access_token: str,
        *,
        required_scope: Optional[List[str]] = None,
        required_permissions: Optional[List[str]] = None,
    ) -> FiefAccessTokenInfo:
        jwks = await self._get_jwks()
        return self._validate_access_token(
            access_token,
            jwks,
            required_scope=required_scope,
            required_permissions=required_permissions,
        )

    async def userinfo(self, access_token: str) -> FiefUserInfo:
        userinfo_endpoint = self._get_endpoint_url(
            await self._get_openid_configuration(), "userinfo_endpoint"
        )
        async with self._get_httpx_client() as client:
            request = self._get_userinfo_request(
                client, endpoint=userinfo_endpoint, access_token=access_token
            )
            response = await client.send(request)

            response.raise_for_status()

            return response.json()

    async def update_profile(
        self, access_token: str, data: Dict[str, Any]
    ) -> FiefUserInfo:
        update_profile_endpoint = f"{self.base_url}/api/profile"

        async with self._get_httpx_client() as client:
            request = self._get_update_profile_request(
                client,
                endpoint=update_profile_endpoint,
                access_token=access_token,
                data=data,
            )
            response = await client.send(request)

            response.raise_for_status()

            return response.json()

    async def logout_url(self, redirect_uri: str) -> str:
        params = {"redirect_uri": redirect_uri}
        return f"{self.base_url}/logout?{urlencode(params)}"

    @contextlib.asynccontextmanager
    async def _get_httpx_client(self):
        headers = {}
        if self.host is not None:
            headers["Host"] = self.host

        async with httpx.AsyncClient(base_url=self.base_url, headers=headers) as client:
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

        jwks_uri = self._get_endpoint_url(
            await self._get_openid_configuration(), "jwks_uri"
        )
        async with self._get_httpx_client() as client:
            response = await client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    async def _auth_exchange_token(
        self, code: str, redirect_uri: str, *, code_verifier: Optional[str] = None
    ) -> FiefTokenResponse:
        token_endpoint = self._get_endpoint_url(
            await self._get_openid_configuration(), "token_endpoint"
        )
        async with self._get_httpx_client() as client:
            request = self._get_auth_exchange_token_request(
                client,
                endpoint=token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )
            response = await client.send(request)

            response.raise_for_status()

            return response.json()
