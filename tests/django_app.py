from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.urls import include, path


def index(request):
    return HttpResponse("Index")


@login_required
def protected(request):
    return HttpResponse(f"Hello, {request.user.email}")


urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("fief_client.integrations.django.urls")),
    path("", index, name="index"),
    path("protected/", protected, name="protected"),
]
