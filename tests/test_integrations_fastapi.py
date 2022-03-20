import uuid
from typing import AsyncGenerator, List

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, status
from fastapi.security.base import SecurityBase
from fastapi.security.http import HTTPBearer
from fastapi.security.oauth2 import OAuth2PasswordBearer

from fief_client.client import Fief, FiefAsync
from fief_client.integrations.fastapi import FiefAuth, FiefClientClass


@pytest.fixture(scope="module", params=[Fief, FiefAsync])
def fief_client(request) -> FiefClientClass:
    fief_class = request.param
    return fief_class("https://bretagne.fief.dev", "CLIENT_ID", "CLIENT_SECRET")


schemes: List[SecurityBase] = [
    HTTPBearer(auto_error=False),
    OAuth2PasswordBearer("/token"),
]


@pytest.fixture(scope="module", params=schemes)
def scheme(request) -> SecurityBase:
    return request.param


@pytest.fixture(scope="module")
def fastapi_app(fief_client: FiefClientClass, scheme: SecurityBase) -> FastAPI:
    auth = FiefAuth(fief_client, scheme)
    app = FastAPI()

    @app.get("/current-user")
    async def get_current_user(user_id: uuid.UUID = Depends(auth.current_user())):
        return {"user_id": str(user_id)}

    @app.get("/current-user-scope")
    async def get_current_user_scope(
        user_id: uuid.UUID = Depends(auth.current_user(scope=["required_scope"])),
    ):
        return {"user_id": str(user_id)}

    return app


@pytest_asyncio.fixture
async def test_client(fastapi_app: FastAPI) -> AsyncGenerator[httpx.AsyncClient, None]:
    async with httpx.AsyncClient(
        app=fastapi_app, base_url="http://api.bretagne.duchy"
    ) as test_client:
        yield test_client


@pytest.mark.asyncio
async def test_openapi(test_client: httpx.AsyncClient, scheme: SecurityBase):
    response = await test_client.get("/openapi.json")

    assert response.status_code == status.HTTP_200_OK

    json = response.json()
    assert scheme.scheme_name in json["components"]["securitySchemes"]


@pytest.mark.asyncio
async def test_missing_token(test_client: httpx.AsyncClient):
    response = await test_client.get("/current-user")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_expired_token(test_client: httpx.AsyncClient, generate_token):
    access_token = generate_token(encrypt=False, exp=0)

    response = await test_client.get(
        "/current-user", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_valid_token(
    test_client: httpx.AsyncClient, generate_token, user_id: str
):
    access_token = generate_token(encrypt=False)

    response = await test_client.get(
        "/current-user", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == status.HTTP_200_OK

    json = response.json()
    assert json == {"user_id": user_id}


@pytest.mark.asyncio
async def test_missing_scope(test_client: httpx.AsyncClient, generate_token):
    access_token = generate_token(encrypt=False, scope="openid")

    response = await test_client.get(
        "/current-user-scope", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_valid_scope(
    test_client: httpx.AsyncClient, generate_token, user_id: str
):
    access_token = generate_token(encrypt=False, scope="openid required_scope")

    response = await test_client.get(
        "/current-user-scope", headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == status.HTTP_200_OK

    json = response.json()
    assert json == {"user_id": user_id}
