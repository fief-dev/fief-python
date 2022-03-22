from fastapi import Depends, FastAPI
from fastapi.security import OAuth2AuthorizationCodeBearer
from fief_client import FiefAccessTokenInfo, FiefAsync
from fief_client.integrations.fastapi import FiefAuth

fief = FiefAsync(
    "https://myworkspace.fief.dev",
    "FIEF_CLIENT_ID",
    "FIEF_CLIENT_SECRET",
)

scheme = OAuth2AuthorizationCodeBearer(
    "https://myworkspace.fief.dev/authorize",
    "https://myworkspace.fief.dev/api/token",
    scopes={"openid": "openid", "offline_access": "offline_access"},
)

auth = FiefAuth(fief, scheme)

app = FastAPI()


@app.get("/user")
async def get_user(
    access_token_info: FiefAccessTokenInfo = Depends(auth.current_user()),
):
    return access_token_info
