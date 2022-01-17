import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlencode

import httpx
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException


@dataclass
class FiefTokenResponse:
    access_token: str
    id_token: str
    token_type: str


class FiefError(Exception):
    pass


class FiefIdTokenInvalidError(FiefError):
    pass


class Fief:
    host: str
    client_id: str
    client_secret: str
    encryption_key: Optional[jwk.JWK] = None

    _openid_configuration: Optional[Dict[str, Any]] = None
    _jwks: Optional[jwk.JWKSet] = None

    def __init__(
        self,
        host: str,
        client_id: str,
        client_secret: str,
        encryption_key: Optional[str] = None,
    ) -> None:
        self.host = host
        self.client_id = client_id
        self.client_secret = client_secret

        if encryption_key is not None:
            self.encryption_key = jwk.JWK.from_json(encryption_key)

    def auth_url(
        self,
        redirect_uri: str,
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

        authorization_endpoint = self._get_openid_configuration()[
            "authorization_endpoint"
        ]
        return f"{authorization_endpoint}?{urlencode(params)}"

    def auth_callback(
        self, code: str, redirect_uri: str
    ) -> Tuple[FiefTokenResponse, Dict[str, Any]]:
        token_response = self._auth_exchange_token(code, redirect_uri)
        userinfo = self._decode_id_token(token_response.id_token)
        return token_response, userinfo

    def _get_openid_configuration(self) -> Dict[str, Any]:
        if self._openid_configuration is not None:
            return self._openid_configuration

        with httpx.Client(base_url=self.host) as client:
            response = client.get("/.well-known/openid-configuration")
            json = response.json()
            self._openid_configuration = json
            return json

    def _get_jwks(self) -> jwk.JWKSet:
        if self._jwks is not None:
            return self._jwks

        jwks_uri = self._get_openid_configuration()["jwks_uri"]
        with httpx.Client() as client:
            response = client.get(jwks_uri)
            self._jwks = jwk.JWKSet.from_json(response.text)
            return self._jwks

    def _auth_exchange_token(self, code: str, redirect_uri) -> FiefTokenResponse:
        token_endpoint = self._get_openid_configuration()["token_endpoint"]
        with httpx.Client() as client:
            response = client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )

            response.raise_for_status()

            return FiefTokenResponse(**response.json())

    def _decode_id_token(self, id_token: str) -> Dict[str, Any]:
        try:
            if self.encryption_key is not None:
                decrypted_id_token = jwt.JWT(jwt=id_token, key=self.encryption_key)
                id_token_claims = decrypted_id_token.claims
            else:
                id_token_claims = id_token

            signed_id_token = jwt.JWT(
                jwt=id_token_claims, algs=["RS256"], key=self._get_jwks()
            )
            return json.loads(signed_id_token.claims)
        except JWException as e:
            raise FiefIdTokenInvalidError() from e
