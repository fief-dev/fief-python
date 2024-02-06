import contextlib
import json
import uuid
from typing import Dict, List, Mapping, Optional, Tuple

import httpx
import pytest
import respx
from httpx import Response
from jwcrypto import jwk
from pytest_mock import MockerFixture

from fief_client.client import (
    Fief,
    FiefAccessTokenACRTooLow,
    FiefAccessTokenExpired,
    FiefAccessTokenInvalid,
    FiefAccessTokenMissingPermission,
    FiefAccessTokenMissingScope,
    FiefACR,
    FiefAsync,
    FiefIdTokenInvalid,
    FiefRequestError,
    FiefTokenResponse,
)
from fief_client.crypto import get_validation_hash
from tests.conftest import GetAPIRequestsMock


@pytest.fixture(scope="module")
def fief_client() -> Fief:
    return Fief("https://bretagne.fief.dev", "CLIENT_ID", "CLIENT_SECRET")


@pytest.fixture(scope="module")
def fief_client_tenant() -> Fief:
    return Fief("https://bretagne.fief.dev/secondary", "CLIENT_ID", "CLIENT_SECRET")


@pytest.fixture(scope="module")
def fief_client_encryption_key(encryption_key: jwk.JWK) -> Fief:
    return Fief(
        "https://bretagne.fief.dev",
        "CLIENT_ID",
        "CLIENT_SECRET",
        encryption_key=encryption_key.export(),
    )


@pytest.fixture(scope="module")
def fief_async_client() -> FiefAsync:
    return FiefAsync("https://bretagne.fief.dev", "CLIENT_ID", "CLIENT_SECRET")


def test_serializable_fief_token_response():
    token_response = FiefTokenResponse(
        access_token="ACCESS_TOKEN",
        id_token="ID_TOKEN",
        token_type="bearer",
        expires_in=3600,
        refresh_token=None,
    )
    assert (
        json.dumps(token_response)
        == '{"access_token": "ACCESS_TOKEN", "id_token": "ID_TOKEN", "token_type": "bearer", "expires_in": 3600, "refresh_token": null}'
    )


def test_fief_acr():
    assert FiefACR.LEVEL_ZERO < FiefACR.LEVEL_ONE
    assert FiefACR.LEVEL_ZERO <= FiefACR.LEVEL_ONE
    assert FiefACR.LEVEL_ONE > FiefACR.LEVEL_ZERO
    assert FiefACR.LEVEL_ONE >= FiefACR.LEVEL_ZERO
    assert FiefACR.LEVEL_ZERO == FiefACR.LEVEL_ZERO


class TestCustomVerifyCertParameters:
    def test_sync(self, mocker: MockerFixture):
        client_mock = mocker.patch.object(httpx, "Client")

        fief = Fief(
            "https://bretagne.fief.dev",
            "CLIENT_ID",
            "CLIENT_SECRET",
            verify=False,
            cert="/bretagne.pem",
        )
        with fief._get_httpx_client() as _:
            client_mock.assert_called_with(
                base_url="https://bretagne.fief.dev",
                headers={},
                verify=False,
                cert="/bretagne.pem",
            )

    @pytest.mark.asyncio
    async def test_async(self, mocker: MockerFixture):
        client_mock = mocker.patch.object(httpx, "AsyncClient")

        @contextlib.asynccontextmanager
        async def client_context_mock(*args, **kwargs):
            yield

        client_mock.side_effect = client_context_mock

        fief = FiefAsync(
            "https://bretagne.fief.dev",
            "CLIENT_ID",
            "CLIENT_SECRET",
            verify=False,
            cert="/bretagne.pem",
        )
        async with fief._get_httpx_client() as _:
            client_mock.assert_called_with(
                base_url="https://bretagne.fief.dev",
                headers={},
                verify=False,
                cert="/bretagne.pem",
            )


class TestAuthURL:
    @pytest.mark.parametrize(
        "state,scope,code_challenge,code_challenge_method,lang,extras_params,expected_params",
        [
            (None, None, None, None, None, None, ""),
            ("STATE", None, None, None, None, None, "&state=STATE"),
            (
                None,
                ["SCOPE_1", "SCOPE_2"],
                None,
                None,
                None,
                None,
                "&scope=SCOPE_1+SCOPE_2",
            ),
            (None, None, None, None, None, {"foo": "bar"}, "&foo=bar"),
            (
                None,
                None,
                "CODE_CHALLENGE",
                "S256",
                None,
                None,
                "&code_challenge=CODE_CHALLENGE&code_challenge_method=S256",
            ),
            (None, None, None, None, "fr-FR", None, "&lang=fr-FR"),
        ],
    )
    def test_authorization_url(
        self,
        state: Optional[str],
        scope: Optional[List[str]],
        code_challenge: Optional[str],
        code_challenge_method: Optional[str],
        lang: Optional[str],
        extras_params: Optional[Mapping[str, str]],
        expected_params: str,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
    ):
        authorize_url = fief_client.auth_url(
            "https://www.bretagne.duchy/callback",
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            lang=lang,
            extras_params=extras_params,
        )
        assert (
            authorize_url
            == f"https://bretagne.fief.dev/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fwww.bretagne.duchy%2Fcallback{expected_params}"
        )

        assert mock_api_requests.calls.last is not None
        request, _ = mock_api_requests.calls.last
        url = str(request.url)
        assert url.startswith(fief_client.base_url)

        assert request.url.host == request.headers["Host"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "state,scope,code_challenge,code_challenge_method,lang,extras_params,expected_params",
        [
            (None, None, None, None, None, None, ""),
            ("STATE", None, None, None, None, None, "&state=STATE"),
            (
                None,
                ["SCOPE_1", "SCOPE_2"],
                None,
                None,
                None,
                None,
                "&scope=SCOPE_1+SCOPE_2",
            ),
            (None, None, None, None, None, {"foo": "bar"}, "&foo=bar"),
            (
                None,
                None,
                "CODE_CHALLENGE",
                "S256",
                None,
                None,
                "&code_challenge=CODE_CHALLENGE&code_challenge_method=S256",
            ),
            (None, None, None, None, "fr-FR", None, "&lang=fr-FR"),
        ],
    )
    async def test_authorization_url_async(
        self,
        state: Optional[str],
        scope: Optional[List[str]],
        code_challenge: Optional[str],
        code_challenge_method: Optional[str],
        lang: Optional[str],
        extras_params: Optional[Mapping[str, str]],
        expected_params: str,
        fief_async_client: FiefAsync,
        mock_api_requests: respx.MockRouter,
    ):
        authorize_url = await fief_async_client.auth_url(
            "https://www.bretagne.duchy/callback",
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            lang=lang,
            extras_params=extras_params,
        )
        assert (
            authorize_url
            == f"https://bretagne.fief.dev/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fwww.bretagne.duchy%2Fcallback{expected_params}"
        )

        assert mock_api_requests.calls.last is not None
        request, _ = mock_api_requests.calls.last
        url = str(request.url)
        assert url.startswith(fief_async_client.base_url)

        assert request.url.host == request.headers["Host"]

    def test_authorization_url_tenant(
        self, fief_client_tenant: Fief, get_api_requests_mock: GetAPIRequestsMock
    ):
        with get_api_requests_mock(path_prefix="/secondary"):
            authorize_url = fief_client_tenant.auth_url(
                "https://www.bretagne.duchy/callback"
            )

        assert (
            authorize_url
            == "https://bretagne.fief.dev/secondary/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fwww.bretagne.duchy%2Fcallback"
        )


class TestAuthCallback:
    def test_error_response(
        self, fief_client: Fief, mock_api_requests: respx.MockRouter
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            fief_client.auth_callback(
                "CODE",
                "https://www.bretagne.duchy/callback",
                code_verifier="CODE_VERIFIER",
            )
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    def test_valid_response(
        self,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
        access_token: str,
        signed_id_token: str,
        user_id: str,
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(
            200,
            json={
                "access_token": access_token,
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        token_response, userinfo = fief_client.auth_callback(
            "CODE", "https://www.bretagne.duchy/callback", code_verifier="CODE_VERIFIER"
        )

        token_route_call = token_route.calls.last
        assert token_route_call is not None

        request_data = token_route_call.request.content.decode("utf-8")
        assert "client_id" in request_data
        assert "client_secret" in request_data

        assert token_response["access_token"] == access_token
        assert token_response["id_token"] == signed_id_token

        assert isinstance(userinfo, dict)
        assert userinfo["sub"] == user_id

    @pytest.mark.asyncio
    async def test_error_response_async(
        self, fief_async_client: FiefAsync, mock_api_requests: respx.MockRouter
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            await fief_async_client.auth_callback(
                "CODE",
                "https://www.bretagne.duchy/callback",
                code_verifier="CODE_VERIFIER",
            )
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    @pytest.mark.asyncio
    async def test_valid_response_async(
        self,
        fief_async_client: FiefAsync,
        mock_api_requests: respx.MockRouter,
        access_token: str,
        signed_id_token: str,
        user_id: str,
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(
            200,
            json={
                "access_token": access_token,
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        token_response, userinfo = await fief_async_client.auth_callback(
            "CODE", "https://www.bretagne.duchy/callback", code_verifier="CODE_VERIFIER"
        )

        token_route_call = token_route.calls.last
        assert token_route_call is not None

        request_data = token_route_call.request.content.decode("utf-8")
        assert "client_id" in request_data
        assert "client_secret" in request_data

        assert token_response["access_token"] == access_token
        assert token_response["id_token"] == signed_id_token

        assert isinstance(userinfo, dict)
        assert userinfo["sub"] == user_id

    def test_valid_response_tenant(
        self,
        fief_client_tenant: Fief,
        get_api_requests_mock: GetAPIRequestsMock,
        access_token: str,
        signed_id_token: str,
        user_id: str,
    ):
        with get_api_requests_mock(path_prefix="/secondary") as mock_api_requests:
            token_route = mock_api_requests.post("/secondary/token")
            token_route.return_value = Response(
                200,
                json={
                    "access_token": access_token,
                    "id_token": signed_id_token,
                    "token_type": "bearer",
                },
            )

            token_response, userinfo = fief_client_tenant.auth_callback(
                "CODE",
                "https://www.bretagne.duchy/callback",
                code_verifier="CODE_VERIFIER",
            )

            token_route_call = token_route.calls.last
            assert token_route_call is not None

            request_data = token_route_call.request.content.decode("utf-8")
            assert "client_id" in request_data
            assert "client_secret" in request_data

            assert token_response["access_token"] == access_token
            assert token_response["id_token"] == signed_id_token

            assert isinstance(userinfo, dict)
            assert userinfo["sub"] == user_id


class TestAuthRefreshToken:
    def test_error_response(
        self, fief_client: Fief, mock_api_requests: respx.MockRouter
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            fief_client.auth_refresh_token(
                "REFRESH_TOKEN", scope=["openid", "offline_access"]
            )
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    def test_valid_response(
        self,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
        access_token: str,
        signed_id_token: str,
        user_id: str,
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(
            200,
            json={
                "access_token": access_token,
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        token_response, userinfo = fief_client.auth_refresh_token(
            "REFRESH_TOKEN", scope=["openid", "offline_access"]
        )

        token_route_call = token_route.calls.last
        assert token_route_call is not None

        request_data = token_route_call.request.content.decode("utf-8")
        assert "client_id" in request_data
        assert "client_secret" in request_data

        assert token_response["access_token"] == access_token
        assert token_response["id_token"] == signed_id_token

        assert isinstance(userinfo, dict)
        assert userinfo["sub"] == user_id

    @pytest.mark.asyncio
    async def test_error_response_async(
        self, fief_async_client: FiefAsync, mock_api_requests: respx.MockRouter
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            await fief_async_client.auth_refresh_token(
                "REFRESH_TOKEN", scope=["openid", "offline_access"]
            )
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    @pytest.mark.asyncio
    async def test_valid_response_async(
        self,
        fief_async_client: FiefAsync,
        mock_api_requests: respx.MockRouter,
        access_token: str,
        signed_id_token: str,
        user_id: str,
    ):
        token_route = mock_api_requests.post("/token")
        token_route.return_value = Response(
            200,
            json={
                "access_token": access_token,
                "id_token": signed_id_token,
                "token_type": "bearer",
            },
        )

        token_response, userinfo = await fief_async_client.auth_refresh_token(
            "REFRESH_TOKEN", scope=["openid", "offline_access"]
        )

        token_route_call = token_route.calls.last
        assert token_route_call is not None

        request_data = token_route_call.request.content.decode("utf-8")
        assert "client_id" in request_data
        assert "client_secret" in request_data

        assert token_response["access_token"] == access_token
        assert token_response["id_token"] == signed_id_token

        assert isinstance(userinfo, dict)
        assert userinfo["sub"] == user_id


class TestValidateAccessToken:
    def test_invalid_token(self, fief_client: Fief):
        with pytest.raises(FiefAccessTokenInvalid):
            fief_client.validate_access_token("INVALID_TOKEN")

    def test_invalid_signature(self, fief_client: Fief):
        with pytest.raises(FiefAccessTokenInvalid):
            fief_client.validate_access_token(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )

    def test_invalid_claims(self, fief_client: Fief):
        with pytest.raises(FiefAccessTokenInvalid):
            fief_client.validate_access_token(
                "eyJhbGciOiJSUzI1NiJ9.e30.RmKxjgPljzJL_-Yp9oBJIvNejvES_pnTeZBDvptYcdWm4Ze9D6FlM8RFJ5-ZJ3O-HXlWylVXiGAE_wdSGXehSaENUN3Mj91j5OfiXGrtBGSiEiCtC9HYKCi6xf6xmcEPoTbtBVi38a9OARoJlpTJ5T4BbmqIUR8R06sqo3zTkwk48wPmYtk_OPgMv4c8tNyHF17dRe1JM_ix-m7V1Nv_2DHLMRgMXdsWkl0RCcAFQwqCTXU4UxWSoXp6CB0-Ybkq-P5KyXIXy0b15qG8jfgCrFHqFhN3hpyvL4Zza_EkXJaCkB5v-oztlHS6gTGb3QgFqppW3JM6TJnDKslGRPDsjg"
            )

    def test_invalid_acr_claim(self, fief_client: Fief, generate_access_token):
        access_token = generate_access_token(encrypt=False, acr="INVALID_ACR")
        with pytest.raises(FiefAccessTokenInvalid):
            fief_client.validate_access_token(access_token)

    def test_expired(self, fief_client: Fief, generate_access_token):
        access_token = generate_access_token(encrypt=False, exp=0)
        with pytest.raises(FiefAccessTokenExpired):
            fief_client.validate_access_token(access_token)

    def test_missing_scope(self, fief_client: Fief, generate_access_token):
        access_token = generate_access_token(
            encrypt=False, scope="openid offline_access"
        )
        with pytest.raises(FiefAccessTokenMissingScope):
            fief_client.validate_access_token(access_token, required_scope=["REQUIRED"])

    def test_valid_scope(self, fief_client: Fief, generate_access_token, user_id: str):
        access_token = generate_access_token(
            encrypt=False, scope="openid offline_access"
        )
        info = fief_client.validate_access_token(
            access_token, required_scope=["openid"]
        )
        assert info == {
            "id": uuid.UUID(user_id),
            "scope": ["openid", "offline_access"],
            "acr": FiefACR.LEVEL_ZERO,
            "permissions": [],
            "access_token": access_token,
        }

    def test_invalid_acr(self, fief_client: Fief, generate_access_token):
        access_token = generate_access_token(encrypt=False, acr=FiefACR.LEVEL_ZERO)
        with pytest.raises(FiefAccessTokenACRTooLow):
            fief_client.validate_access_token(
                access_token, required_acr=FiefACR.LEVEL_ONE
            )

    def test_valid_acr(self, fief_client: Fief, generate_access_token, user_id: str):
        access_token = generate_access_token(encrypt=False, acr=FiefACR.LEVEL_ONE)
        info = fief_client.validate_access_token(
            access_token, required_acr=FiefACR.LEVEL_ONE
        )
        assert info == {
            "id": uuid.UUID(user_id),
            "scope": [],
            "acr": FiefACR.LEVEL_ONE,
            "permissions": [],
            "access_token": access_token,
        }

    def test_missing_permission(self, fief_client: Fief, generate_access_token):
        access_token = generate_access_token(
            encrypt=False, permissions=["castles:read"]
        )
        with pytest.raises(FiefAccessTokenMissingPermission):
            fief_client.validate_access_token(
                access_token, required_permissions=["castles:create"]
            )

    def test_valid_permission(
        self, fief_client: Fief, generate_access_token, user_id: str
    ):
        access_token = generate_access_token(
            encrypt=False, permissions=["castles:read", "castles:create"]
        )
        info = fief_client.validate_access_token(
            access_token, required_permissions=["castles:create"]
        )
        assert info == {
            "id": uuid.UUID(user_id),
            "scope": [],
            "acr": FiefACR.LEVEL_ZERO,
            "permissions": ["castles:read", "castles:create"],
            "access_token": access_token,
        }

    @pytest.mark.asyncio
    async def test_async_invalid_token(self, fief_async_client: FiefAsync):
        with pytest.raises(FiefAccessTokenInvalid):
            await fief_async_client.validate_access_token("INVALID_TOKEN")

    @pytest.mark.asyncio
    async def test_async_invalid_signature(self, fief_async_client: FiefAsync):
        with pytest.raises(FiefAccessTokenInvalid):
            await fief_async_client.validate_access_token(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )

    @pytest.mark.asyncio
    async def test_async_invalid_claims(self, fief_async_client: FiefAsync):
        with pytest.raises(FiefAccessTokenInvalid):
            await fief_async_client.validate_access_token(
                "eyJhbGciOiJSUzI1NiJ9.e30.RmKxjgPljzJL_-Yp9oBJIvNejvES_pnTeZBDvptYcdWm4Ze9D6FlM8RFJ5-ZJ3O-HXlWylVXiGAE_wdSGXehSaENUN3Mj91j5OfiXGrtBGSiEiCtC9HYKCi6xf6xmcEPoTbtBVi38a9OARoJlpTJ5T4BbmqIUR8R06sqo3zTkwk48wPmYtk_OPgMv4c8tNyHF17dRe1JM_ix-m7V1Nv_2DHLMRgMXdsWkl0RCcAFQwqCTXU4UxWSoXp6CB0-Ybkq-P5KyXIXy0b15qG8jfgCrFHqFhN3hpyvL4Zza_EkXJaCkB5v-oztlHS6gTGb3QgFqppW3JM6TJnDKslGRPDsjg"
            )

    @pytest.mark.asyncio
    async def test_async_expired(
        self, fief_async_client: FiefAsync, generate_access_token
    ):
        access_token = generate_access_token(encrypt=False, exp=0)
        with pytest.raises(FiefAccessTokenExpired):
            await fief_async_client.validate_access_token(access_token)

    @pytest.mark.asyncio
    async def test_async_missing_scope(
        self, fief_async_client: FiefAsync, generate_access_token
    ):
        access_token = generate_access_token(
            encrypt=False, scope="openid offline_access"
        )
        with pytest.raises(FiefAccessTokenMissingScope):
            await fief_async_client.validate_access_token(
                access_token, required_scope=["REQUIRED"]
            )

    @pytest.mark.asyncio
    async def test_async_valid_scope(
        self, fief_async_client: FiefAsync, generate_access_token, user_id: str
    ):
        access_token = generate_access_token(
            encrypt=False, scope="openid offline_access"
        )
        info = await fief_async_client.validate_access_token(
            access_token, required_scope=["openid"]
        )
        assert info == {
            "id": uuid.UUID(user_id),
            "scope": ["openid", "offline_access"],
            "acr": FiefACR.LEVEL_ZERO,
            "permissions": [],
            "access_token": access_token,
        }

    @pytest.mark.asyncio
    async def test_async_invalid_acr(
        self, fief_async_client: FiefAsync, generate_access_token
    ):
        access_token = generate_access_token(encrypt=False, acr=FiefACR.LEVEL_ZERO)
        with pytest.raises(FiefAccessTokenACRTooLow):
            await fief_async_client.validate_access_token(
                access_token, required_acr=FiefACR.LEVEL_ONE
            )

    @pytest.mark.asyncio
    async def test_async_valid_acr(
        self, fief_async_client: FiefAsync, generate_access_token, user_id: str
    ):
        access_token = generate_access_token(encrypt=False, acr=FiefACR.LEVEL_ONE)
        info = await fief_async_client.validate_access_token(
            access_token, required_acr=FiefACR.LEVEL_ONE
        )
        assert info == {
            "id": uuid.UUID(user_id),
            "scope": [],
            "acr": FiefACR.LEVEL_ONE,
            "permissions": [],
            "access_token": access_token,
        }

    @pytest.mark.asyncio
    async def test_async_missing_permission(
        self, fief_async_client: FiefAsync, generate_access_token
    ):
        access_token = generate_access_token(
            encrypt=False, permissions=["castles:read"]
        )
        with pytest.raises(FiefAccessTokenMissingPermission):
            await fief_async_client.validate_access_token(
                access_token, required_permissions=["castles:create"]
            )

    @pytest.mark.asyncio
    async def test_async_valid_permission(
        self, fief_async_client: FiefAsync, generate_access_token, user_id: str
    ):
        access_token = generate_access_token(
            encrypt=False, permissions=["castles:read", "castles:create"]
        )
        info = await fief_async_client.validate_access_token(
            access_token, required_permissions=["castles:create"]
        )
        assert info == {
            "id": uuid.UUID(user_id),
            "scope": [],
            "acr": FiefACR.LEVEL_ZERO,
            "permissions": ["castles:read", "castles:create"],
            "access_token": access_token,
        }


class TestUserinfo:
    def test_error_response(
        self, fief_client: Fief, mock_api_requests: respx.MockRouter
    ):
        token_route = mock_api_requests.get("/userinfo")
        token_route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            fief_client.userinfo("ACCESS_TOKEN")
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    def test_valid_response(
        self, fief_client: Fief, mock_api_requests: respx.MockRouter, user_id: str
    ):
        mock_api_requests.get("/userinfo").return_value = Response(
            200, json={"sub": user_id}
        )

        userinfo = fief_client.userinfo("ACCESS_TOKEN")
        assert userinfo == {"sub": user_id}

    @pytest.mark.asyncio
    async def test_error_response_async(
        self, fief_async_client: FiefAsync, mock_api_requests: respx.MockRouter
    ):
        token_route = mock_api_requests.get("/userinfo")
        token_route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            await fief_async_client.userinfo("ACCESS_TOKEN")
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    @pytest.mark.asyncio
    async def test_valid_response_async(
        self,
        fief_async_client: FiefAsync,
        mock_api_requests: respx.MockRouter,
        user_id: str,
    ):
        mock_api_requests.get("/userinfo").return_value = Response(
            200, json={"sub": user_id}
        )

        userinfo = await fief_async_client.userinfo("ACCESS_TOKEN")
        assert userinfo == {"sub": user_id}


@pytest.mark.parametrize(
    "endpoint,method_name,args",
    [
        (
            "/api/profile",
            "update_profile",
            ("ACCESS_TOKEN", {"fields": {"first_name": "Anne"}}),
        ),
        ("/api/password", "change_password", ("ACCESS_TOKEN", "herminetincture")),
        ("/api/email/change", "email_change", ("ACCESS_TOKEN", "anne@nantes.city")),
        ("/api/email/verify", "email_verify", ("ACCESS_TOKEN", "ABCDE")),
    ],
)
class TestUpdateUserMethods:
    def test_error_response(
        self,
        endpoint: str,
        method_name: str,
        args: Tuple,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
    ):
        route = mock_api_requests.route(path=endpoint)
        route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            method = getattr(fief_client, method_name)
            method(*args)
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    def test_valid_response(
        self,
        endpoint: str,
        method_name: str,
        args: Tuple,
        fief_client: Fief,
        mock_api_requests: respx.MockRouter,
        user_id: str,
    ):
        mock_api_requests.route(path=endpoint).return_value = Response(
            200, json={"sub": user_id}
        )

        method = getattr(fief_client, method_name)
        userinfo = method(*args)
        assert userinfo == {"sub": user_id}

    @pytest.mark.asyncio
    async def test_error_response_async(
        self,
        endpoint: str,
        method_name: str,
        args: Tuple,
        fief_async_client: FiefAsync,
        mock_api_requests: respx.MockRouter,
    ):
        route = mock_api_requests.route(path=endpoint)
        route.return_value = Response(400, json={"detail": "error"})

        with pytest.raises(FiefRequestError) as excinfo:
            method = getattr(fief_async_client, method_name)
            await method(*args)
        assert excinfo.value.status_code == 400
        assert excinfo.value.detail == '{"detail": "error"}'

    @pytest.mark.asyncio
    async def test_valid_response_async(
        self,
        endpoint: str,
        method_name: str,
        args: Tuple,
        fief_async_client: FiefAsync,
        mock_api_requests: respx.MockRouter,
        user_id: str,
    ):
        mock_api_requests.route(path=endpoint).return_value = Response(
            200, json={"sub": user_id}
        )

        method = getattr(fief_async_client, method_name)
        userinfo = await method(*args)
        assert userinfo == {"sub": user_id}


class TestLogoutURL:
    def test_logout_url(self, fief_client: Fief):
        logout_url = fief_client.logout_url("https://www.bretagne.duchy")
        assert (
            logout_url
            == "https://bretagne.fief.dev/logout?redirect_uri=https%3A%2F%2Fwww.bretagne.duchy"
        )

    @pytest.mark.asyncio
    async def test_logout_url_async(self, fief_async_client: FiefAsync):
        logout_url = await fief_async_client.logout_url("https://www.bretagne.duchy")
        assert (
            logout_url
            == "https://bretagne.fief.dev/logout?redirect_uri=https%3A%2F%2Fwww.bretagne.duchy"
        )


class TestDecodeIdToken:
    def test_signed_valid(
        self,
        fief_client: Fief,
        signed_id_token: str,
        signature_key: jwk.JWK,
        user_id: str,
    ):
        claims = fief_client._decode_id_token(signed_id_token, signature_key)
        assert claims["sub"] == user_id

    def test_signed_invalid(self, fief_client: Fief, signature_key: jwk.JWK):
        with pytest.raises(FiefIdTokenInvalid):
            fief_client._decode_id_token(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                signature_key,
            )

    def test_encrypted_valid(
        self,
        fief_client_encryption_key: Fief,
        encrypted_id_token: str,
        signature_key: jwk.JWK,
        user_id: str,
    ):
        claims = fief_client_encryption_key._decode_id_token(
            encrypted_id_token, signature_key
        )
        assert claims["sub"] == user_id

    def test_encrypted_without_key(
        self, fief_client: Fief, encrypted_id_token: str, signature_key: jwk.JWK
    ):
        with pytest.raises(FiefIdTokenInvalid):
            fief_client._decode_id_token(encrypted_id_token, signature_key)

    def test_encrypted_invalid(
        self, fief_client_encryption_key: Fief, signature_key: jwk.JWK
    ):
        with pytest.raises(FiefIdTokenInvalid):
            fief_client_encryption_key._decode_id_token(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                signature_key,
            )

    def test_signed_at_hash_c_hash_valid(
        self,
        fief_client: Fief,
        signature_key: jwk.JWK,
        user_id: str,
        generate_token,
    ):
        id_token = generate_token(
            encrypt=False,
            c_hash=get_validation_hash("CODE"),
            at_hash=get_validation_hash("ACCESS_TOKEN"),
        )
        claims = fief_client._decode_id_token(
            id_token, signature_key, code="CODE", access_token="ACCESS_TOKEN"
        )
        assert claims["sub"] == user_id

    @pytest.mark.parametrize(
        "claims",
        [
            {"c_hash": get_validation_hash("INVALID_CODE")},
            {"at_hash": get_validation_hash("INVALID_ACCESS_TOKEN")},
            {
                "c_hash": get_validation_hash("INVALID_CODE"),
                "at_hash": get_validation_hash("INVALID_ACCESS_TOKEN"),
            },
        ],
    )
    def test_signed_at_hash_c_hash_invalid(
        self,
        claims: Dict[str, str],
        fief_client: Fief,
        signature_key: jwk.JWK,
        generate_token,
    ):
        id_token = generate_token(encrypt=False, **claims)
        with pytest.raises(FiefIdTokenInvalid):
            fief_client._decode_id_token(
                id_token, signature_key, code="CODE", access_token="ACCESS_TOKEN"
            )


class TestExplicitHost:
    def test_sync_client(self, mock_api_requests: respx.MockRouter):
        client = Fief(
            "http://localhost:8000",
            "CLIENT_ID",
            "CLIENT_SECRET",
            host="www.bretagne.duchy",
        )

        client.auth_url("https://www.bretagne.duchy/callback")

        assert mock_api_requests.calls.last is not None
        request, _ = mock_api_requests.calls.last
        url = str(request.url)
        assert url.startswith("http://localhost:8000")
        assert request.headers["Host"] == "www.bretagne.duchy"

    @pytest.mark.asyncio
    async def test_async_client(self, mock_api_requests: respx.MockRouter):
        client = FiefAsync(
            "http://localhost:8000",
            "CLIENT_ID",
            "CLIENT_SECRET",
            host="www.bretagne.duchy",
        )

        await client.auth_url("https://www.bretagne.duchy/callback")

        assert mock_api_requests.calls.last is not None
        request, _ = mock_api_requests.calls.last
        url = str(request.url)
        assert url.startswith("http://localhost:8000")
        assert request.headers["Host"] == "www.bretagne.duchy"
