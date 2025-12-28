"""
URLs for logs app.
"""
from django.urls import path
from . import views
from .views_servers import servers_list, update_server, toggle_server, delete_server, migrate_server

app_name = 'logs'

urlpatterns = [
    path('', views.log_list, name='list'),
    
    # Server management
    path('servers/', servers_list, name='servers_list'),
    path('servers/<int:server_id>/update/', update_server, name='update_server'),
    path('servers/<int:server_id>/toggle/', toggle_server, name='toggle_server'),
    path('servers/<int:server_id>/delete/', delete_server, name='delete_server'),
    path('servers/<int:server_id>/migrate/', migrate_server, name='migrate_server'),
]
