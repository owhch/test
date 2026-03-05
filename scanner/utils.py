import socket
import ssl
import json
from urllib.parse import urlparse
from datetime import datetime

import requests


def analyze_url(url: str) -> dict:
    """Run all security checks on a URL and return results."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    results = {
        'url': url,
        'checks': [],
        'score': 0,
        'total_checks': 0,
        'passed_checks': 0,
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        results['error'] = f'Не удалось подключиться: {str(e)}'
        return results

    # --- Check HTTPS ---
    check_https(url, results)

    # --- Check Security Headers ---
    check_header(headers, 'Strict-Transport-Security', 'HSTS',
                 'Защищает от downgrade-атак и перехвата cookie', results)
    check_header(headers, 'Content-Security-Policy', 'CSP',
                 'Предотвращает XSS и инъекции данных', results)
    check_header(headers, 'X-Content-Type-Options', 'X-Content-Type-Options',
                 'Предотвращает MIME-sniffing', results)
    check_header(headers, 'X-Frame-Options', 'X-Frame-Options',
                 'Защищает от clickjacking-атак', results)
    check_header(headers, 'X-XSS-Protection', 'X-XSS-Protection',
                 'Дополнительная защита от XSS', results)
    check_header(headers, 'Referrer-Policy', 'Referrer-Policy',
                 'Контролирует передачу Referer', results)
    check_header(headers, 'Permissions-Policy', 'Permissions-Policy',
                 'Контролирует доступ к API браузера', results)

    # --- Check SSL Certificate ---
    check_ssl(url, results)

    # --- Check Server Header ---
    check_server_header(headers, results)

    # --- Check Cookies ---
    check_cookies(response, results)

    # --- Calculate Score ---
    total = results['total_checks']
    passed = results['passed_checks']
    results['score'] = round((passed / total) * 100) if total > 0 else 0

    return results


def check_https(url, results):
    results['total_checks'] += 1
    is_https = url.startswith('https://')
    results['checks'].append({
        'name': 'HTTPS',
        'passed': is_https,
        'value': 'Да' if is_https else 'Нет',
        'description': 'Шифрование трафика между клиентом и сервером',
        'severity': 'critical',
    })
    if is_https:
        results['passed_checks'] += 1


def check_header(headers, header_name, display_name, description, results):
    results['total_checks'] += 1
    value = headers.get(header_name)
    passed = value is not None
    results['checks'].append({
        'name': display_name,
        'passed': passed,
        'value': value if passed else 'Отсутствует',
        'description': description,
        'severity': 'high' if display_name in ['CSP', 'HSTS'] else 'medium',
    })
    if passed:
        results['passed_checks'] += 1


def check_ssl(url, results):
    results['total_checks'] += 1
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.utcnow()).days
                passed = days_left > 30
                results['checks'].append({
                    'name': 'SSL-сертификат',
                    'passed': passed,
                    'value': f'Действителен ещё {days_left} дней',
                    'description': 'Проверка срока действия SSL-сертификата',
                    'severity': 'critical',
                })
                if passed:
                    results['passed_checks'] += 1
    except Exception as e:
        results['checks'].append({
            'name': 'SSL-сертификат',
            'passed': False,
            'value': f'Ошибка проверки: {str(e)[:80]}',
            'description': 'Проверка срока действия SSL-сертификата',
            'severity': 'critical',
        })


def check_server_header(headers, results):
    results['total_checks'] += 1
    server = headers.get('Server')
    passed = server is None
    results['checks'].append({
        'name': 'Server Header',
        'passed': passed,
        'value': 'Скрыт' if passed else server,
        'description': 'Раскрытие Server-заголовка помогает атакующему определить ПО',
        'severity': 'low',
    })
    if passed:
        results['passed_checks'] += 1


def check_cookies(response, results):
    results['total_checks'] += 1
    cookies = response.cookies
    if not cookies:
        results['checks'].append({
            'name': 'Cookie Security',
            'passed': True,
            'value': 'Cookie не обнаружены',
            'description': 'Проверка флагов Secure, HttpOnly, SameSite',
            'severity': 'medium',
        })
        results['passed_checks'] += 1
        return

    issues = []
    for cookie in cookies:
        if not cookie.secure:
            issues.append(f'{cookie.name}: нет Secure')
        if 'httponly' not in cookie._rest:
            issues.append(f'{cookie.name}: нет HttpOnly')

    passed = len(issues) == 0
    results['checks'].append({
        'name': 'Cookie Security',
        'passed': passed,
        'value': 'Все флаги на месте' if passed else '; '.join(issues[:3]),
        'description': 'Проверка флагов Secure, HttpOnly, SameSite',
        'severity': 'medium',
    })
    if passed:
        results['passed_checks'] += 1
