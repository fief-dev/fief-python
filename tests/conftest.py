from datetime import datetime, timezone
from os import path
from typing import Callable

import pytest
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
def generate_id_token(signature_key: jwk.JWK, encryption_key: jwk.JWK):
    def _generate_id_token(encrypt: bool) -> str:
        iat = int(datetime.now(timezone.utc).timestamp())
        exp = iat + 3600

        claims = {
            "sub": "USER_ID",
            "email": "anne@bretagne.duchy",
            "iss": "https://bretagne.fief.dev",
            "aud": ["CLIENT_ID"],
            "exp": exp,
            "iat": iat,
            "azp": "CLIENT_ID",
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

    return _generate_id_token


@pytest.fixture(scope="session")
def signed_id_token(generate_id_token: Callable[..., str]) -> str:
    return generate_id_token(encrypt=False)


@pytest.fixture(scope="session")
def encrypted_id_token(generate_id_token: Callable[..., str]) -> str:
    return generate_id_token(encrypt=True)
