from typing import Generator, List, Mapping, Optional

import pytest
import pytest_asyncio
import respx
from httpx import Response
from jwcrypto import jwk

from fief_client.client import Fief, FiefIdTokenInvalidError

HOSTNAME = "https://bretagne.fief.dev"


@pytest_asyncio.fixture(scope="module", autouse=True)
def mock_api_requests(
    signature_key: jwk.JWK,
) -> Generator[respx.MockRouter, None, None]:
    with respx.mock(assert_all_mocked=True) as respx_mock:
        openid_configuration_route = respx_mock.get("/.well-known/openid-configuration")
        openid_configuration_route.return_value = Response(
            200,
            json={
                "authorization_endpoint": f"{HOSTNAME}/auth/authorize",
                "token_endpoint": f"{HOSTNAME}/auth/token",
                "jwks_uri": f"{HOSTNAME}/.well-known/jwks.json",
            },
        )

        jwks_route = respx_mock.get("/.well-known/jwks.json")
        jwks_route.return_value = Response(
            200, json={"keys": [signature_key.export(private_key=False, as_dict=True)]}
        )

        yield respx_mock


@pytest.fixture(scope="module", params=[None, "http://localhost:8000"])
def fief_client(request) -> Fief:
    return Fief(
        "https://bretagne.fief.dev",
        "CLIENT_ID",
        "CLIENT_SECRET",
        internal_host=request.param,
    )


@pytest.fixture(scope="module")
def fief_client_encryption_key(encryption_key: jwk.JWK) -> Fief:
    return Fief(
        "https://bretagne.fief.dev",
        "CLIENT_ID",
        "CLIENT_SECRET",
        encryption_key=encryption_key.export(),
    )


class TestAuthURL:
    @pytest.mark.parametrize(
        "state,scope,extras_params,expected_params",
        [
            (None, None, None, ""),
            ("STATE", None, None, "&state=STATE"),
            (None, ["SCOPE_1", "SCOPE_2"], None, "&scope=SCOPE_1+SCOPE_2"),
            (None, None, {"foo": "bar"}, "&foo=bar"),
        ],
    )
    def test_authorization_url(
        self,
        state: Optional[str],
        scope: Optional[List[str]],
        extras_params: Optional[Mapping[str, str]],
        expected_params: str,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
    ):
        authorize_url = fief_client.auth_url(
            "https://www.bretagne.duchy/callback",
            state=state,
            scope=scope,
            extras_params=extras_params,
        )
        assert (
            authorize_url
            == f"https://bretagne.fief.dev/auth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fwww.bretagne.duchy%2Fcallback{expected_params}"
        )

        assert mock_api_requests.calls.last is not None
        request, _ = mock_api_requests.calls.last
        assert request.headers["Host"] == fief_client.host
        url = str(request.url)
        if fief_client.internal_host is not None:
            assert url.startswith(fief_client.internal_host)
        else:
            assert url.startswith(fief_client.host)


class TestAuthCallback:
    def test_valid_response(
        self,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
        signed_id_token: str,
    ):
        mock_api_requests.post("/auth/token").return_value = Response(
            200,
            json={
                "access_token": "ACCESS_TOKEN",
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        token_response, userinfo = fief_client.auth_callback(
            "CODE", "https://www.bretagne.duchy/callback"
        )
        assert token_response.access_token == "ACCESS_TOKEN"
        assert token_response.id_token == signed_id_token

        assert isinstance(userinfo, dict)
        assert userinfo["sub"] == "USER_ID"


class TestDecodeIdToken:
    def test_signed_valid(self, fief_client: Fief, signed_id_token: str):
        claims = fief_client._decode_id_token(signed_id_token)
        assert claims["sub"] == "USER_ID"

    def test_signed_invalid(self, fief_client: Fief):
        with pytest.raises(FiefIdTokenInvalidError):
            fief_client._decode_id_token(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )

    def test_encrypted_valid(
        self, fief_client_encryption_key: Fief, encrypted_id_token: str
    ):
        claims = fief_client_encryption_key._decode_id_token(encrypted_id_token)
        assert claims["sub"] == "USER_ID"

    def test_encrypted_without_key(self, fief_client: Fief, encrypted_id_token: str):
        with pytest.raises(FiefIdTokenInvalidError):
            fief_client._decode_id_token(encrypted_id_token)

    def test_encrypted_invalid(self, fief_client_encryption_key: Fief):
        with pytest.raises(FiefIdTokenInvalidError):
            fief_client_encryption_key._decode_id_token(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )
