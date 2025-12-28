"""
Ingest API URLs.
"""
from django.urls import path
from . import views

app_name = 'ingest'

urlpatterns = [
    # Specific endpoints (original)
    path('haproxy/', views.ingest_haproxy, name='ingest_haproxy'),
    path('nginx/', views.ingest_nginx, name='ingest_nginx'),
    path('crowdsec/', views.ingest_crowdsec, name='ingest_crowdsec'),
    path('fail2ban/', views.ingest_fail2ban, name='ingest_fail2ban'),
    path('inventory/services/', views.ingest_service_inventory, name='ingest_service_inventory'),
    
    # Generic endpoint (new)
    path('log/', views.ingest_generic, name='ingest_generic'),
]
