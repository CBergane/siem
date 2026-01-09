"""
Dashboard URLs.
"""
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_overview, name='overview'),
    path('inventory/', views.inventory_overview, name='inventory_overview'),
    path('partials/recent-logs/', views.recent_logs_partial, name='recent_logs_partial'),
    path('partials/stats/', views.stats_partial, name='stats_partial'),
    path('api/timeline/', views.timeline_data, name='timeline_data'),
    path('api/geographic/', views.geographic_data, name='geographic_data'),
    path('api/isp-stats/', views.isp_stats_data, name='isp_stats_data'),
]
