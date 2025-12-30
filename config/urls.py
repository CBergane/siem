from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from apps.core import views as core_views
from apps.organizations import views as org_views

urlpatterns = [
    path("health/", core_views.health_check, name="health_check"),
    path("", include("apps.core.urls")),
    path("org/settings/keys/", org_views.org_keys, name="org_settings_keys"),
    path("org/settings/agents/", org_views.org_agents, name="org_settings_agents"),
    path("org/settings/install/", org_views.org_install, name="org_settings_install"),

    path("secure-admin-panel/", admin.site.urls),

    path("api/v1/ingest/", include("apps.ingest.urls")),

    # allauth
    path("accounts/", include("allauth.urls")),

    # dashboard (ONLY ONCE)
    path("dashboard/", include("apps.dashboard.urls")),

    path("logs/", include("apps.logs.urls")),
    path("alerts/", include("apps.alerts.urls")),
    path("organizations/", include("apps.organizations.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
