import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from scanner.models import Scan, ScanResult, Vulnerability

VULN_CATALOG = {
    'missing_header_csp': {
        'name': 'Missing Content-Security-Policy Header',
        'severity': 'high',
        'description': 'The response does not include a Content-Security-Policy header.',
        'recommendation': 'Define a strict Content-Security-Policy to reduce XSS risk.',
    },
    'missing_header_xfo': {
        'name': 'Missing X-Frame-Options Header',
        'severity': 'medium',
        'description': 'The response does not include X-Frame-Options.',
        'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN.',
    },
    'missing_header_hsts': {
        'name': 'Missing Strict-Transport-Security Header',
        'severity': 'high',
        'description': 'HSTS is missing and transport security enforcement is weak.',
        'recommendation': 'Enable Strict-Transport-Security with a strong max-age.',
    },
    'insecure_transport': {
        'name': 'Insecure Transport (HTTP)',
        'severity': 'high',
        'description': 'Target URL is using HTTP, which may expose sensitive traffic.',
        'recommendation': 'Force HTTPS and redirect all HTTP traffic to HTTPS.',
    },
    'cookie_missing_secure': {
        'name': 'Cookie Missing Secure Flag',
        'severity': 'medium',
        'description': 'Set-Cookie header present without Secure flag.',
        'recommendation': 'Mark sensitive cookies as Secure.',
    },
    'cookie_missing_httponly': {
        'name': 'Cookie Missing HttpOnly Flag',
        'severity': 'medium',
        'description': 'Set-Cookie header present without HttpOnly flag.',
        'recommendation': 'Set HttpOnly to limit JavaScript access to cookies.',
    },
    'reflected_input': {
        'name': 'Potential Reflected Input/XSS',
        'severity': 'high',
        'description': 'Injected reflected probe appears in response body.',
        'recommendation': 'Sanitize and escape all user-controlled output.',
    },
    'sqli_form_input_name': {
        'name': 'Potential SQL Injection Surface in Form Fields',
        'severity': 'medium',
        'description': 'Form fields suggest query-critical inputs requiring strict validation.',
        'recommendation': 'Use server-side validation and parameterized ORM/database queries.',
    },
}

SEVERITY_WEIGHT = {'low': 5, 'medium': 12, 'high': 20}


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f'https://{url}'
        parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('Only http and https URLs are allowed.')
    if not parsed.netloc:
        raise ValueError('Invalid URL: missing host.')
    return urlunparse(parsed._replace(fragment=''))


def _get_or_create_vuln(code: str) -> Vulnerability:
    data = VULN_CATALOG[code]
    vuln, _ = Vulnerability.objects.get_or_create(
        code=code,
        defaults={
            'name': data['name'],
            'severity': data['severity'],
            'description': data['description'],
            'recommendation': data['recommendation'],
        },
    )
    return vuln


def _record(scan: Scan, code: str, detected: bool, evidence: str = '') -> None:
    vuln = _get_or_create_vuln(code)
    ScanResult.objects.update_or_create(
        scan=scan,
        vulnerability=vuln,
        defaults={'detected': detected, 'evidence': evidence},
    )


def enforce_rate_limit(user_id: int | None, ip: str) -> None:
    quota = settings.SCAN_RATE_LIMIT_PER_HOUR
    key = f'webguard:scan:user:{user_id}' if user_id else f'webguard:scan:ip:{ip}'
    current = cache.get(key, 0)
    if current >= quota:
        raise ValueError('Rate limit reached. Please wait and try again later.')
    cache.set(key, current + 1, timeout=3600)


def _check_security_headers(scan: Scan, response: requests.Response):
    mapping = {
        'Content-Security-Policy': 'missing_header_csp',
        'X-Frame-Options': 'missing_header_xfo',
        'Strict-Transport-Security': 'missing_header_hsts',
    }
    for header, code in mapping.items():
        present = header in response.headers
        _record(scan, code, not present, f'{header} present={present}')


def _check_cookie_flags(scan: Scan, response: requests.Response):
    cookies = response.headers.get('Set-Cookie', '')
    if not cookies:
        _record(scan, 'cookie_missing_secure', False, 'No Set-Cookie header present.')
        _record(scan, 'cookie_missing_httponly', False, 'No Set-Cookie header present.')
        return
    low = cookies.lower()
    _record(scan, 'cookie_missing_secure', 'secure' not in low, cookies[:400])
    _record(scan, 'cookie_missing_httponly', 'httponly' not in low, cookies[:400])


def _check_https(scan: Scan):
    insecure = urlparse(scan.normalized_url).scheme != 'https'
    _record(scan, 'insecure_transport', insecure, f'Scheme={urlparse(scan.normalized_url).scheme}')


def _check_reflected_input(scan: Scan):
    token = 'webguard_probe_xss_123'
    parsed = urlparse(scan.normalized_url)
    query = parse_qs(parsed.query)
    query['webguard_probe'] = [token]
    probe_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    try:
        probe_resp = requests.get(probe_url, timeout=settings.REQUEST_TIMEOUT_SECONDS, allow_redirects=True)
        _record(scan, 'reflected_input', token in probe_resp.text, f'Probe URL={probe_url}')
    except requests.RequestException:
        _record(scan, 'reflected_input', False, 'Probe request failed.')


def _check_forms_for_sqli_surface(scan: Scan, response: requests.Response):
    soup = BeautifulSoup(response.text, 'html.parser')
    names = []
    for field in soup.find_all('input'):
        name = (field.get('name') or '').lower()
        if re.search(r'(search|query|id|user|email|name)', name):
            names.append(name)
    evidence = f'Suspicious fields: {", ".join(sorted(set(names)))}' if names else 'No suspicious form fields.'
    _record(scan, 'sqli_form_input_name', bool(names), evidence)


def _calculate_score_and_risk(scan: Scan):
    findings = scan.results.select_related('vulnerability').filter(detected=True)
    penalty = sum(SEVERITY_WEIGHT.get(r.vulnerability.severity.lower(), 5) for r in findings)
    score = max(0, 100 - penalty)
    scan.security_score = score
    scan.risk_level = Scan.RiskLevel.LOW if score >= 75 else Scan.RiskLevel.MEDIUM if score >= 45 else Scan.RiskLevel.HIGH


def run_scan(scan_id: int):
    scan = Scan.objects.get(pk=scan_id)
    started = time.perf_counter()
    scan.status = Scan.Status.RUNNING
    scan.started_at = timezone.now()
    scan.error_message = ''
    scan.save(update_fields=['status', 'started_at', 'error_message'])

    try:
        response = requests.get(scan.normalized_url, timeout=settings.REQUEST_TIMEOUT_SECONDS, allow_redirects=True)
        _check_security_headers(scan, response)
        _check_cookie_flags(scan, response)
        _check_https(scan)
        _check_reflected_input(scan)
        _check_forms_for_sqli_surface(scan, response)
        _calculate_score_and_risk(scan)
        scan.status = Scan.Status.COMPLETED
    except requests.RequestException as exc:
        scan.status = Scan.Status.FAILED
        scan.risk_level = Scan.RiskLevel.HIGH
        scan.security_score = 0
        scan.error_message = f'Could not scan target: {exc}'
    finally:
        scan.scan_duration_ms = int((time.perf_counter() - started) * 1000)
        scan.completed_at = timezone.now()
        scan.save(update_fields=['status', 'risk_level', 'security_score', 'scan_duration_ms', 'completed_at', 'error_message'])
