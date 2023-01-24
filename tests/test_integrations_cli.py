import concurrent.futures
import json
import tempfile
from typing import BinaryIO, Generator
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from pytest_mock import MockerFixture

from fief_client.client import FiefAccessTokenExpired
from fief_client.integrations.cli import (
    FiefAuth,
    FiefAuthAuthorizationCodeMissingError,
    FiefAuthNotAuthenticatedError,
    FiefAuthRefreshTokenMissingError,
)


@pytest.fixture()
def fief_client() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def credentials_file() -> Generator[BinaryIO, None, None]:
    with tempfile.NamedTemporaryFile() as file:
        yield file  # type: ignore


@pytest.fixture(autouse=True)
def webbrowser_open_mock(mocker: MockerFixture) -> MagicMock:
    return mocker.patch("webbrowser.open")


class TestAuthorize:
    def test_valid_code(
        self,
        fief_client: MagicMock,
        credentials_file: BinaryIO,
        webbrowser_open_mock: MagicMock,
    ):
        fief_client.auth_callback.return_value = (
            {"access_token": "ACCESS_TOKEN", "refresh_token": "REFRESH_TOKEN"},
            {"email": "anne@bretagne.duchy"},
        )
        fief_auth = FiefAuth(fief_client, credentials_file.name)

        with respx.mock(assert_all_mocked=False) as respx_mock:
            respx_mock.get("http://localhost:51562/callback").pass_through()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                authorize_task = executor.submit(fief_auth.authorize)
                with httpx.Client() as client:
                    response = client.get(
                        "http://localhost:51562/callback",
                        params={"code": "AUTHORIZATION_CODE"},
                    )
                    assert response.status_code == 200
                    assert (
                        response.headers["content-type"] == "text/html; charset=utf-8"
                    )
                authorize_task.result()

        webbrowser_open_mock.assert_called_once()

        credentials_file_content = credentials_file.read()
        assert credentials_file_content != ""
        assert json.loads(credentials_file_content) == {
            "userinfo": {"email": "anne@bretagne.duchy"},
            "tokens": {
                "access_token": "ACCESS_TOKEN",
                "refresh_token": "REFRESH_TOKEN",
            },
        }

    def test_missing_code(self, fief_client: MagicMock, credentials_file: BinaryIO):
        fief_auth = FiefAuth(fief_client, credentials_file.name)

        with respx.mock(assert_all_mocked=False) as respx_mock:
            respx_mock.get("http://localhost:51562/callback").pass_through()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                authorize_task = executor.submit(fief_auth.authorize)
                with httpx.Client() as client:
                    response = client.get("http://localhost:51562/callback", params={})
                    assert response.status_code == 400
                    assert (
                        response.headers["content-type"] == "text/html; charset=utf-8"
                    )
                with pytest.raises(FiefAuthAuthorizationCodeMissingError):
                    authorize_task.result()


class TestAccessTokenInfo:
    def test_no_saved_credentials(
        self, fief_client: MagicMock, credentials_file: BinaryIO
    ):
        fief_auth = FiefAuth(fief_client, credentials_file.name)
        with pytest.raises(FiefAuthNotAuthenticatedError):
            fief_auth.access_token_info()

    def test_valid_token(self, fief_client: MagicMock, credentials_file: BinaryIO):
        credentials_file.write(
            json.dumps(
                {
                    "userinfo": {"email": "anne@bretagne.duchy"},
                    "tokens": {
                        "access_token": "ACCESS_TOKEN",
                        "refresh_token": "REFRESH_TOKEN",
                    },
                }
            ).encode("utf-8")
        )
        credentials_file.seek(0)

        access_token_info = {
            "id": "USER_ID",
            "scope": ["openid", "offline_access"],
            "permissions": [],
            "access_token": "ACCESS_TOKEN",
        }
        fief_client.validate_access_token.return_value = access_token_info

        fief_auth = FiefAuth(fief_client, credentials_file.name)
        assert fief_auth.access_token_info() == access_token_info

    def test_expired_token_refresh(
        self, fief_client: MagicMock, credentials_file: BinaryIO
    ):
        credentials_file.write(
            json.dumps(
                {
                    "userinfo": {"email": "anne@bretagne.duchy"},
                    "tokens": {
                        "access_token": "EXPIRED_ACCESS_TOKEN",
                        "refresh_token": "REFRESH_TOKEN",
                    },
                }
            ).encode("utf-8")
        )
        credentials_file.seek(0)

        access_token_info = {
            "id": "USER_ID",
            "scope": ["openid", "offline_access"],
            "permissions": [],
            "access_token": "ACCESS_TOKEN",
        }

        def validate_access_token_mock(access_token: str):
            if access_token == "EXPIRED_ACCESS_TOKEN":
                raise FiefAccessTokenExpired()
            return access_token_info

        fief_client.validate_access_token.side_effect = validate_access_token_mock
        fief_client.auth_refresh_token.return_value = (
            {"access_token": "ACCESS_TOKEN", "refresh_token": "REFRESH_TOKEN"},
            {"email": "anne@bretagne.duchy"},
        )

        fief_auth = FiefAuth(fief_client, credentials_file.name)
        assert fief_auth.access_token_info() == access_token_info
        fief_client.auth_refresh_token.assert_called_once_with("REFRESH_TOKEN")

    def test_expired_token_missing_refresh_token(
        self, fief_client: MagicMock, credentials_file: BinaryIO
    ):
        credentials_file.write(
            json.dumps(
                {
                    "userinfo": {"email": "anne@bretagne.duchy"},
                    "tokens": {"access_token": "EXPIRED_ACCESS_TOKEN"},
                }
            ).encode("utf-8")
        )
        credentials_file.seek(0)

        fief_client.validate_access_token.side_effect = FiefAccessTokenExpired()

        fief_auth = FiefAuth(fief_client, credentials_file.name)
        with pytest.raises(FiefAuthRefreshTokenMissingError):
            fief_auth.access_token_info()

    def test_expired_token_no_refresh(
        self, fief_client: MagicMock, credentials_file: BinaryIO
    ):
        credentials_file.write(
            json.dumps(
                {
                    "userinfo": {"email": "anne@bretagne.duchy"},
                    "tokens": {"access_token": "EXPIRED_ACCESS_TOKEN"},
                }
            ).encode("utf-8")
        )
        credentials_file.seek(0)

        fief_client.validate_access_token.side_effect = FiefAccessTokenExpired()

        fief_auth = FiefAuth(fief_client, credentials_file.name)
        with pytest.raises(FiefAccessTokenExpired):
            fief_auth.access_token_info(refresh=False)


class TestCurrentUser:
    def test_no_saved_credentials(
        self, fief_client: MagicMock, credentials_file: BinaryIO
    ):
        fief_auth = FiefAuth(fief_client, credentials_file.name)
        with pytest.raises(FiefAuthNotAuthenticatedError):
            fief_auth.current_user()

    def test_no_refresh(self, fief_client: MagicMock, credentials_file: BinaryIO):
        credentials_file.write(
            json.dumps(
                {
                    "userinfo": {"email": "anne@bretagne.duchy"},
                    "tokens": {
                        "access_token": "ACCESS_TOKEN",
                        "refresh_token": "REFRESH_TOKEN",
                    },
                }
            ).encode("utf-8")
        )
        credentials_file.seek(0)

        fief_auth = FiefAuth(fief_client, credentials_file.name)
        assert fief_auth.current_user() == {"email": "anne@bretagne.duchy"}

    def test_refresh(self, fief_client: MagicMock, credentials_file: BinaryIO):
        credentials_file.write(
            json.dumps(
                {
                    "userinfo": {"email": "anne@bretagne.duchy"},
                    "tokens": {
                        "access_token": "ACCESS_TOKEN",
                        "refresh_token": "REFRESH_TOKEN",
                    },
                }
            ).encode("utf-8")
        )
        credentials_file.seek(0)

        fief_client.userinfo.return_value = {"email": "anne+updated@bretagne.duchy"}

        fief_auth = FiefAuth(fief_client, credentials_file.name)
        assert fief_auth.current_user(refresh=True) == {
            "email": "anne+updated@bretagne.duchy"
        }
