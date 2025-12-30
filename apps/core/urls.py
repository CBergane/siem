from django.urls import path
from .views import (
    home,
    LandingPageView,
    custom_login_view,
    request_join,
    super_join_requests,
    super_tenants,
    super_tenant_detail,
    agents_placeholder,
)

urlpatterns = [
    path("", home, name="home"),
    path("landing/", LandingPageView.as_view(), name="landing"),
    path("login/", custom_login_view, name="login"),
    path("request-join/", request_join, name="request_join"),
    path("agents/", agents_placeholder, name="agents_placeholder"),
    path("super/join-requests/", super_join_requests, name="super_join_requests"),
    path("super/tenants/", super_tenants, name="super_tenants"),
    path("super/tenants/<slug:slug>/", super_tenant_detail, name="super_tenant_detail"),
]
