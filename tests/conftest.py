import uuid
from datetime import datetime, timezone
from os import path
from typing import Callable, Generator

import pytest
import pytest_asyncio
import respx
from httpx import Response
from jwcrypto import jwk, jwt


@pytest.fixture(scope="session")
def keys() -> jwk.JWKSet:
    with open(path.join(path.dirname(__file__), "jwks.json"), "r") as jwks_file:
        return jwk.JWKSet.from_json(jwks_file.read())


@pytest.fixture(scope="session")
def signature_key(keys: jwk.JWKSet) -> jwk.JWK:
    return keys.get_key("fief-client-tests-sig")


@pytest.fixture(scope="session")
def encryption_key(keys: jwk.JWKSet) -> jwk.JWK:
    return keys.get_key("fief-client-tests-enc")


@pytest.fixture(scope="session")
def user_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture(scope="session")
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture(scope="session")
def generate_token(
    signature_key: jwk.JWK, encryption_key: jwk.JWK, user_id: str, tenant_id: str
):
    def _generate_token(encrypt: bool, **kwargs) -> str:
        iat = int(datetime.now(timezone.utc).timestamp())
        exp = iat + 3600

        claims = {
            "sub": user_id,
            "email": "anne@bretagne.duchy",
            "tenant_id": tenant_id,
            "is_active": True,
            "is_superuser": False,
            "is_verified": True,
            "iss": "https://bretagne.fief.dev",
            "aud": ["CLIENT_ID"],
            "exp": exp,
            "iat": iat,
            "azp": "CLIENT_ID",
            **kwargs,
        }

        signed_token = jwt.JWT(header={"alg": "RS256"}, claims=claims)
        signed_token.make_signed_token(signature_key)

        if encrypt:
            encrypted_token = jwt.JWT(
                header={"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512"},
                claims=signed_token.serialize(),
            )
            encrypted_token.make_encrypted_token(encryption_key)
            return encrypted_token.serialize()

        return signed_token.serialize()

    return _generate_token


@pytest.fixture(scope="session")
def access_token(generate_token: Callable[..., str]) -> str:
    return generate_token(encrypt=False)


@pytest.fixture(scope="session")
def signed_id_token(generate_token: Callable[..., str]) -> str:
    return generate_token(encrypt=False)


@pytest.fixture(scope="session")
def encrypted_id_token(generate_token: Callable[..., str]) -> str:
    return generate_token(encrypt=True)


@pytest_asyncio.fixture(scope="module", autouse=True)
def mock_api_requests(
    signature_key: jwk.JWK,
) -> Generator[respx.MockRouter, None, None]:
    HOSTNAME = "https://bretagne.fief.dev"

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as respx_mock:
        openid_configuration_route = respx_mock.get("/.well-known/openid-configuration")
        openid_configuration_route.return_value = Response(
            200,
            json={
                "authorization_endpoint": f"{HOSTNAME}/authorize",
                "token_endpoint": f"{HOSTNAME}/token",
                "userinfo_endpoint": f"{HOSTNAME}/userinfo",
                "jwks_uri": f"{HOSTNAME}/.well-known/jwks.json",
            },
        )

        jwks_route = respx_mock.get("/.well-known/jwks.json")
        jwks_route.return_value = Response(
            200, json={"keys": [signature_key.export(private_key=False, as_dict=True)]}
        )

        yield respx_mock
