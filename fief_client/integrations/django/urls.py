from django.urls import path

from fief_client.integrations.django import views

urlpatterns = [
    path("login/", views.login),
    path("logout/", views.logout),
    path("callback/", views.callback, name="callback"),
]
