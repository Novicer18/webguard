from django.conf import settings
from django.db import models


class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    class RiskLevel(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    target_url = models.URLField(max_length=500)
    normalized_url = models.URLField(max_length=500)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    risk_level = models.CharField(max_length=20, choices=RiskLevel.choices, default=RiskLevel.LOW)
    security_score = models.PositiveSmallIntegerField(default=100)
    scan_duration_ms = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']


class Vulnerability(models.Model):
    code = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    severity = models.CharField(max_length=20)
    description = models.TextField()
    recommendation = models.TextField()

    def __str__(self):
        return self.name


class ScanResult(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='results')
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='findings')
    evidence = models.TextField(blank=True)
    detected = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('scan', 'vulnerability')
