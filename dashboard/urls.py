from django.urls import path

from dashboard import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_home, name='home'),
    path('scans/<int:scan_id>/', views.scan_detail, name='scan-detail'),
]
