from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from rest_framework import permissions, response, status
from rest_framework.decorators import api_view, permission_classes

from scanner.forms import ScanSubmissionForm
from scanner.models import Scan
from scanner.serializers import ScanCreateSerializer, ScanSerializer
from scanner.services.engine import enforce_rate_limit, normalize_url
from scanner.tasks import enqueue_scan


def _get_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    return forwarded.split(',')[0].strip() if forwarded else request.META.get('REMOTE_ADDR', 'unknown')


@login_required
def create_scan(request):
    if request.method == 'POST':
        form = ScanSubmissionForm(request.POST)
        if form.is_valid():
            try:
                enforce_rate_limit(request.user.id, _get_ip(request))
                normalized = normalize_url(form.cleaned_data['target_url'])
            except ValueError as exc:
                messages.error(request, str(exc))
                return redirect('dashboard:home')

            scan = Scan.objects.create(
                user=request.user,
                target_url=form.cleaned_data['target_url'],
                normalized_url=normalized,
            )
            enqueue_scan(scan.id)
            messages.success(request, 'Scan submitted. Results will appear shortly.')
            return redirect('dashboard:scan-detail', scan_id=scan.id)
    return redirect('dashboard:home')


@login_required
def export_scan_pdf(request, scan_id):
    scan = get_object_or_404(Scan.objects.prefetch_related('results__vulnerability'), pk=scan_id, user=request.user)
    out = HttpResponse(content_type='application/pdf')
    out['Content-Disposition'] = f'attachment; filename="webguard_scan_{scan.id}.pdf"'

    pdf = canvas.Canvas(out, pagesize=letter)
    y = 760
    pdf.setFont('Helvetica-Bold', 14)
    pdf.drawString(72, y, f'WebGuard Security Report #{scan.id}')
    y -= 24
    pdf.setFont('Helvetica', 10)
    pdf.drawString(72, y, f'Target: {scan.normalized_url}')
    y -= 16
    pdf.drawString(72, y, f'Status: {scan.status} | Score: {scan.security_score} | Risk: {scan.risk_level}')
    y -= 24

    for result in scan.results.select_related('vulnerability').all():
        if y < 80:
            pdf.showPage()
            y = 760
        vuln = result.vulnerability
        pdf.setFont('Helvetica-Bold', 10)
        pdf.drawString(72, y, f'{vuln.name} ({vuln.severity.upper()}) - Detected: {result.detected}')
        y -= 14
        pdf.setFont('Helvetica', 9)
        pdf.drawString(72, y, f'Recommendation: {vuln.recommendation[:100]}')
        y -= 18

    pdf.save()
    return out


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def api_create_scan(request):
    serializer = ScanCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    enforce_rate_limit(request.user.id, _get_ip(request))
    scan = Scan.objects.create(
        user=request.user,
        target_url=request.data.get('target_url'),
        normalized_url=serializer.validated_data['target_url'],
    )
    enqueue_scan(scan.id)
    return response.Response(ScanSerializer(scan).data, status=status.HTTP_202_ACCEPTED)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def api_scan_detail(request, scan_id):
    scan = get_object_or_404(Scan.objects.prefetch_related('results__vulnerability'), pk=scan_id, user=request.user)
    return response.Response(ScanSerializer(scan).data)
