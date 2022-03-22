from fastapi import Depends, FastAPI
from fastapi.security import OAuth2AuthorizationCodeBearer
from fief_client import FiefAccessTokenInfo, FiefAsync
from fief_client.integrations.fastapi import FiefAuth

fief = FiefAsync(
    "https://example.fief.dev",
    "Esmd4zdQyPvYCNm9d-jFNLQSdi9nzUr5zQYi_GBnVkY",
    "6w_gaoTmw4C9qI0AjUZeFbLWtCPK86QgxA7srPDW8w0",
)

scheme = OAuth2AuthorizationCodeBearer(
    "https://example.fief.dev/authorize",
    "https://example.fief.dev/api/token",
    scopes={"openid": "openid", "offline_access": "offline_access"},
)

auth = FiefAuth(fief, scheme)

app = FastAPI()


@app.get("/user")
async def get_user(
    access_token_info: FiefAccessTokenInfo = Depends(auth.current_user()),
):
    return access_token_info
