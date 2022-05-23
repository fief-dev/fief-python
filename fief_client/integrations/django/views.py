import uuid

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as dj_login
from django.contrib.auth import logout as dj_logout
from django.http import HttpRequest
from django.shortcuts import redirect, resolve_url
from django.urls import reverse

from fief_client.integrations.django.client import get_fief_client

NEXT_PATH_KEY = "_auth_next_path"


def login(request: HttpRequest):
    redirect_uri = request.build_absolute_uri(reverse("callback"))
    next = request.GET.get("next")
    if next is not None:
        request.session[NEXT_PATH_KEY] = next
    fief = get_fief_client()
    authorization_url = fief.auth_url(redirect_uri, scope=settings.FIEF_SCOPE)
    return redirect(authorization_url)


def callback(request: HttpRequest):
    redirect_uri = request.build_absolute_uri(reverse("callback"))
    fief = get_fief_client()
    _, userinfo = fief.auth_callback(request.GET["code"], redirect_uri)
    user = authenticate(
        request, fief_id=uuid.UUID(userinfo["sub"]), email=userinfo["email"]
    )
    if user is not None:
        dj_login(request, user)

    next = request.session.get(NEXT_PATH_KEY)
    if next is not None:
        del request.session[NEXT_PATH_KEY]
        return redirect(next)

    return redirect(resolve_url(settings.LOGIN_REDIRECT_URL))


def logout(request: HttpRequest):
    dj_logout(request)
    redirect_uri = request.build_absolute_uri(resolve_url(settings.LOGOUT_REDIRECT_URL))
    fief = get_fief_client()
    logout_url = fief.logout_url(redirect_uri)
    return redirect(logout_url)
