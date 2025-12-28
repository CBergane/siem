from django.urls import path
from .views import home, LandingPageView, custom_login_view, request_join

urlpatterns = [
    path("", home, name="home"),
    path("landing/", LandingPageView.as_view(), name="landing"),
    path("login/", custom_login_view, name="login"),
    path("request-join/", request_join, name="request_join"),
]
