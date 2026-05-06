from django.urls import path

from dashboard import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_home, name='home'),
    path('about/', views.about_page, name='about'),
    path('scans/<int:scan_id>/', views.scan_detail, name='scan-detail'),
]
