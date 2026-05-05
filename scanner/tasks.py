from concurrent.futures import ThreadPoolExecutor

from django.core.mail import send_mail
from django.template.loader import render_to_string

from scanner.models import Scan
from scanner.services.engine import run_scan

executor = ThreadPoolExecutor(max_workers=4)


def _run_scan_and_notify(scan_id: int):
    run_scan(scan_id)
    scan = Scan.objects.select_related('user').get(pk=scan_id)
    if scan.user.email:
        subject = f'WebGuard scan completed for {scan.normalized_url}'
        body = render_to_string('scanner/email_scan_complete.txt', {'scan': scan})
        send_mail(subject, body, None, [scan.user.email], fail_silently=True)


def enqueue_scan(scan_id: int):
    executor.submit(_run_scan_and_notify, scan_id)
