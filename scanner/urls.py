from django.urls import path

from scanner import views

app_name = 'scanner'

urlpatterns = [
    path('submit/', views.create_scan, name='submit'),
    path('<int:scan_id>/export-pdf/', views.export_scan_pdf, name='export-pdf'),
    path('api/scans/', views.api_create_scan, name='api-create-scan'),
    path('api/scans/<int:scan_id>/', views.api_scan_detail, name='api-scan-detail'),
]
