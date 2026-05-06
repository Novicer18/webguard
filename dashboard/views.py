from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render

from scanner.forms import ScanSubmissionForm
from scanner.models import Scan


def about_page(request):
    return render(request, 'dashboard/about.html')


@login_required
def dashboard_home(request):
    scans = Scan.objects.filter(user=request.user).order_by('-created_at')
    context = {
        'scan_form': ScanSubmissionForm(),
        'scans': scans[:10],
        'total_scans': scans.count(),
        'high_risk_scans': scans.filter(risk_level=Scan.RiskLevel.HIGH).count(),
        'completed_scans': scans.filter(status=Scan.Status.COMPLETED).count(),
    }
    return render(request, 'dashboard/home.html', context)


@login_required
def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan.objects.prefetch_related('results__vulnerability'), pk=scan_id, user=request.user)
    results = scan.results.select_related('vulnerability').order_by('-detected', 'vulnerability__severity')
    return render(request, 'dashboard/scan_detail.html', {'scan': scan, 'results': results})
