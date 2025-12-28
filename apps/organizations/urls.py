"""
Organization URL Configuration.
"""
from django.urls import path
from django.views.generic import TemplateView

app_name = 'organizations'

urlpatterns = [
    # Placeholder
    path('', TemplateView.as_view(template_name='organizations/placeholder.html'), name='list'),
]
