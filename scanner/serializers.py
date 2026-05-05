from rest_framework import serializers

from scanner.models import Scan, ScanResult
from scanner.services.engine import normalize_url


class ScanCreateSerializer(serializers.Serializer):
    target_url = serializers.URLField()

    def validate_target_url(self, value):
        try:
            return normalize_url(value)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc


class ScanResultSerializer(serializers.ModelSerializer):
    vulnerability = serializers.StringRelatedField()
    severity = serializers.CharField(source='vulnerability.severity')

    class Meta:
        model = ScanResult
        fields = ('vulnerability', 'severity', 'detected', 'evidence')


class ScanSerializer(serializers.ModelSerializer):
    results = ScanResultSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = ('id', 'target_url', 'normalized_url', 'status', 'risk_level', 'security_score', 'error_message', 'created_at', 'completed_at', 'results')
