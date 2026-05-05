from django.contrib import admin

from .models import Scan, ScanResult, Vulnerability


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'normalized_url', 'status', 'risk_level', 'security_score', 'created_at')
    list_filter = ('status', 'risk_level', 'created_at')
    search_fields = ('normalized_url', 'user__username')


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'severity')


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('scan', 'vulnerability', 'detected', 'created_at')
