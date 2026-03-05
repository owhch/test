import socket
import ssl
import re
import json
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime

import requests

# Suppress InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ──────────────────────────────────────────────
#  VULNERABILITY DATABASE
# ──────────────────────────────────────────────

VULN_DATABASE = {
    'missing_https': {
        'id': 'VULN-001',
        'name': 'Отсутствие HTTPS',
        'severity': 'critical',
        'cvss': 9.1,
        'category': 'Шифрование',
        'description': 'Сайт не использует HTTPS-шифрование. Весь трафик между пользователем и сервером передаётся в открытом виде.',
        'impact': 'Атакующий может перехватить пароли, cookie, персональные данные через атаку Man-in-the-Middle.',
        'fix': 'Установите SSL-сертификат (Let\'s Encrypt бесплатно) и настройте принудительный редирект на HTTPS.',
        'references': ['CWE-319: Cleartext Transmission of Sensitive Information'],
    },
    'missing_hsts': {
        'id': 'VULN-002',
        'name': 'Отсутствие HSTS',
        'severity': 'high',
        'cvss': 7.4,
        'category': 'Заголовки',
        'description': 'Заголовок Strict-Transport-Security отсутствует. Браузер не принуждается к использованию HTTPS.',
        'impact': 'Возможна SSL-stripping атака: атакующий может перенаправить пользователя на HTTP-версию сайта.',
        'fix': 'Добавьте заголовок: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'references': ['CWE-523: Unprotected Transport of Credentials'],
    },
    'missing_csp': {
        'id': 'VULN-003',
        'name': 'Отсутствие Content-Security-Policy',
        'severity': 'high',
        'cvss': 7.2,
        'category': 'Заголовки',
        'description': 'CSP-заголовок не настроен. Нет ограничений на загрузку скриптов, стилей и других ресурсов.',
        'impact': 'Повышенный риск XSS-атак. Злоумышленник может внедрить и выполнить произвольный JavaScript-код.',
        'fix': 'Настройте Content-Security-Policy с whitelist разрешённых источников: default-src \'self\'; script-src \'self\'',
        'references': ['CWE-693: Protection Mechanism Failure'],
    },
    'missing_xcto': {
        'id': 'VULN-004',
        'name': 'Отсутствие X-Content-Type-Options',
        'severity': 'medium',
        'cvss': 5.3,
        'category': 'Заголовки',
        'description': 'Браузер может неправильно интерпретировать MIME-тип содержимого (MIME-sniffing).',
        'impact': 'Атакующий может заставить браузер выполнить файл как скрипт, что приведёт к XSS.',
        'fix': 'Добавьте заголовок: X-Content-Type-Options: nosniff',
        'references': ['CWE-430: Deployment of Wrong Handler'],
    },
    'missing_xfo': {
        'id': 'VULN-005',
        'name': 'Отсутствие X-Frame-Options',
        'severity': 'medium',
        'cvss': 5.4,
        'category': 'Заголовки',
        'description': 'Сайт может быть встроен в iframe на вредоносной странице.',
        'impact': 'Clickjacking — пользователь кликает по скрытым элементам вашего сайта, думая что взаимодействует с другой страницей.',
        'fix': 'Добавьте заголовок: X-Frame-Options: DENY или SAMEORIGIN',
        'references': ['CWE-1021: Improper Restriction of Rendered UI Layers'],
    },
    'missing_xxss': {
        'id': 'VULN-006',
        'name': 'Отсутствие X-XSS-Protection',
        'severity': 'low',
        'cvss': 3.7,
        'category': 'Заголовки',
        'description': 'Встроенный XSS-фильтр браузера не активирован явно.',
        'impact': 'Современные браузеры обычно включают защиту по умолчанию, но явная настройка обеспечивает совместимость.',
        'fix': 'Добавьте заголовок: X-XSS-Protection: 1; mode=block',
        'references': ['CWE-79: Cross-site Scripting'],
    },
    'missing_referrer': {
        'id': 'VULN-007',
        'name': 'Отсутствие Referrer-Policy',
        'severity': 'low',
        'cvss': 3.1,
        'category': 'Приватность',
        'description': 'Не контролируется передача заголовка Referer при переходах на другие сайты.',
        'impact': 'URL с конфиденциальными параметрами (токены, ID сессий) могут утечь через Referer.',
        'fix': 'Добавьте: Referrer-Policy: strict-origin-when-cross-origin',
        'references': ['CWE-200: Exposure of Sensitive Information'],
    },
    'missing_permissions': {
        'id': 'VULN-008',
        'name': 'Отсутствие Permissions-Policy',
        'severity': 'low',
        'cvss': 3.5,
        'category': 'Приватность',
        'description': 'Не ограничен доступ к API браузера (камера, микрофон, геолокация).',
        'impact': 'Встроенные iframe могут получить доступ к чувствительным API браузера.',
        'fix': 'Добавьте: Permissions-Policy: camera=(), microphone=(), geolocation=()',
        'references': ['CWE-272: Least Privilege Violation'],
    },
    'server_exposed': {
        'id': 'VULN-009',
        'name': 'Раскрытие Server-заголовка',
        'severity': 'info',
        'cvss': 2.6,
        'category': 'Утечка информации',
        'description': 'Сервер раскрывает информацию о своём ПО в заголовке Server.',
        'impact': 'Атакующий узнаёт тип и версию веб-сервера, что упрощает поиск эксплойтов.',
        'fix': 'Скройте заголовок Server или замените его значение на кастомное.',
        'references': ['CWE-200: Exposure of Sensitive Information'],
    },
    'powered_by_exposed': {
        'id': 'VULN-010',
        'name': 'Раскрытие X-Powered-By',
        'severity': 'info',
        'cvss': 2.6,
        'category': 'Утечка информации',
        'description': 'Заголовок X-Powered-By раскрывает используемый фреймворк или язык программирования.',
        'impact': 'Помогает атакующему определить стек технологий и найти специфичные уязвимости.',
        'fix': 'Удалите заголовок X-Powered-By из ответов сервера.',
        'references': ['CWE-200: Exposure of Sensitive Information'],
    },
    'ssl_expiring': {
        'id': 'VULN-011',
        'name': 'SSL-сертификат истекает',
        'severity': 'high',
        'cvss': 7.5,
        'category': 'Шифрование',
        'description': 'SSL-сертификат скоро истечёт.',
        'impact': 'После истечения браузеры будут показывать предупреждение, пользователи потеряют доверие к сайту.',
        'fix': 'Обновите SSL-сертификат. При использовании Let\'s Encrypt настройте автопродление через certbot renew.',
        'references': ['CWE-295: Improper Certificate Validation'],
    },
    'ssl_invalid': {
        'id': 'VULN-012',
        'name': 'Проблемы с SSL-сертификатом',
        'severity': 'critical',
        'cvss': 9.0,
        'category': 'Шифрование',
        'description': 'Не удалось проверить SSL-сертификат.',
        'impact': 'Подключение может быть перехвачено атакующим.',
        'fix': 'Установите валидный SSL-сертификат от доверенного CA.',
        'references': ['CWE-295: Improper Certificate Validation'],
    },
    'cookie_insecure': {
        'id': 'VULN-013',
        'name': 'Небезопасные Cookie',
        'severity': 'medium',
        'cvss': 5.4,
        'category': 'Сессии',
        'description': 'Cookie не имеют необходимых флагов безопасности.',
        'impact': 'Cookie могут быть перехвачены через XSS (без HttpOnly) или MITM (без Secure).',
        'fix': 'Установите флаги: Secure, HttpOnly, SameSite=Strict для всех cookie.',
        'references': ['CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute'],
    },
    'open_redirect': {
        'id': 'VULN-014',
        'name': 'Потенциальный Open Redirect',
        'severity': 'medium',
        'cvss': 5.0,
        'category': 'Редиректы',
        'description': 'Обнаружены подозрительные паттерны перенаправления.',
        'impact': 'Атакующий может перенаправить пользователей на фишинговый сайт.',
        'fix': 'Проверяйте и ограничивайте URL для редиректов. Используйте whitelist разрешённых доменов.',
        'references': ['CWE-601: URL Redirection to Untrusted Site'],
    },
}


# ──────────────────────────────────────────────
#  TECHNOLOGY DETECTION
# ──────────────────────────────────────────────

TECH_SIGNATURES = {
    'headers': {
        'X-Powered-By': {
            'PHP': 'PHP', 'Express': 'Express.js', 'ASP.NET': 'ASP.NET',
            'Next.js': 'Next.js', 'Servlet': 'Java Servlet',
        },
        'Server': {
            'nginx': 'Nginx', 'Apache': 'Apache', 'cloudflare': 'Cloudflare',
            'Microsoft-IIS': 'IIS', 'LiteSpeed': 'LiteSpeed', 'Vercel': 'Vercel',
            'gws': 'Google Web Server', 'AmazonS3': 'Amazon S3',
        },
        'X-Generator': {
            'WordPress': 'WordPress', 'Drupal': 'Drupal', 'Joomla': 'Joomla',
        },
    },
    'body': [
        (r'wp-content|wp-includes', 'WordPress'),
        (r'<meta name="generator" content="WordPress', 'WordPress'),
        (r'Drupal\.settings', 'Drupal'),
        (r'<meta name="generator" content="Joomla', 'Joomla'),
        (r'react\.production\.min\.js|__NEXT_DATA__', 'React'),
        (r'vue\.runtime|Vue\.js', 'Vue.js'),
        (r'angular[\./]', 'Angular'),
        (r'jquery[\./]|jQuery', 'jQuery'),
        (r'bootstrap[\./]', 'Bootstrap'),
        (r'tailwindcss|tailwind\.', 'Tailwind CSS'),
        (r'<meta name="generator" content="Hugo', 'Hugo'),
        (r'Powered by.*Django|csrfmiddlewaretoken', 'Django'),
        (r'Laravel|laravel', 'Laravel'),
        (r'shopify\.com|Shopify\.theme', 'Shopify'),
        (r'googletagmanager\.com|gtag\(', 'Google Tag Manager'),
        (r'google-analytics\.com|GoogleAnalyticsObject', 'Google Analytics'),
        (r'cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com', 'CDN'),
        (r'fonts\.googleapis\.com|fonts\.gstatic\.com', 'Google Fonts'),
    ],
    'cookies': {
        '__cfduid': 'Cloudflare', 'PHPSESSID': 'PHP', 'ASP.NET_SessionId': 'ASP.NET',
        'JSESSIONID': 'Java', 'csrftoken': 'Django', 'laravel_session': 'Laravel',
    }
}


# ──────────────────────────────────────────────
#  PORT SCANNER
# ──────────────────────────────────────────────

COMMON_PORTS = {
    21: ('FTP', 'Файловый трансфер'),
    22: ('SSH', 'Удалённый доступ'),
    25: ('SMTP', 'Почтовый сервер'),
    53: ('DNS', 'DNS-сервер'),
    80: ('HTTP', 'Веб-сервер'),
    110: ('POP3', 'Почтовый сервер'),
    143: ('IMAP', 'Почтовый сервер'),
    443: ('HTTPS', 'Защищённый веб'),
    445: ('SMB', 'Файловый доступ Windows'),
    993: ('IMAPS', 'Защищённая почта'),
    995: ('POP3S', 'Защищённая почта'),
    3306: ('MySQL', 'База данных'),
    3389: ('RDP', 'Удалённый рабочий стол'),
    5432: ('PostgreSQL', 'База данных'),
    6379: ('Redis', 'Кэш/БД'),
    8080: ('HTTP-ALT', 'Альтернативный веб'),
    8443: ('HTTPS-ALT', 'Альтернативный HTTPS'),
    27017: ('MongoDB', 'База данных'),
}


def scan_port(host, port, timeout=1.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None


def scan_ports(host):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                service, desc = COMMON_PORTS[result]
                risk = 'danger' if result in (21, 25, 445, 3306, 3389, 5432, 6379, 27017) else \
                       'warning' if result in (22, 110, 143, 8080) else 'safe'
                open_ports.append({
                    'port': result,
                    'service': service,
                    'description': desc,
                    'risk': risk,
                })
    return sorted(open_ports, key=lambda x: x['port'])


# ──────────────────────────────────────────────
#  TECH DETECTION
# ──────────────────────────────────────────────

def detect_technologies(response):
    techs = set()
    headers = response.headers

    for header, sigs in TECH_SIGNATURES['headers'].items():
        val = headers.get(header, '')
        for pattern, name in sigs.items():
            if pattern.lower() in val.lower():
                techs.add(name)

    try:
        body = response.text[:50000]
        for pattern, name in TECH_SIGNATURES['body']:
            if re.search(pattern, body, re.IGNORECASE):
                techs.add(name)
    except:
        pass

    for cookie_name, tech in TECH_SIGNATURES['cookies'].items():
        if cookie_name in response.cookies:
            techs.add(tech)

    return sorted(list(techs))


# ──────────────────────────────────────────────
#  MAIN ANALYZER
# ──────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    results = {
        'url': url,
        'hostname': hostname,
        'ip_address': None,
        'checks': [],
        'vulnerabilities': [],
        'technologies': [],
        'open_ports': [],
        'score': 0,
        'total_checks': 0,
        'passed_checks': 0,
        'scan_time': 0,
    }

    # Resolve IP
    try:
        results['ip_address'] = socket.gethostbyname(hostname)
    except:
        pass

    import time
    start = time.time()

    # Fetch page
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False,
                                headers={'User-Agent': 'SHIELD-Scanner/2.0'})
        headers = response.headers
    except requests.exceptions.RequestException as e:
        results['error'] = f'Не удалось подключиться: {str(e)}'
        return results

    # ── CHECKS & VULNS ──

    # HTTPS
    results['total_checks'] += 1
    is_https = url.startswith('https://') or response.url.startswith('https://')
    results['checks'].append({
        'name': 'HTTPS', 'passed': is_https,
        'value': 'Включено' if is_https else 'Отсутствует',
        'description': 'Шифрование трафика между клиентом и сервером',
        'severity': 'critical',
    })
    if is_https:
        results['passed_checks'] += 1
    else:
        results['vulnerabilities'].append(VULN_DATABASE['missing_https'])

    # Security headers
    header_checks = [
        ('Strict-Transport-Security', 'HSTS', 'missing_hsts', 'high'),
        ('Content-Security-Policy', 'CSP', 'missing_csp', 'high'),
        ('X-Content-Type-Options', 'X-Content-Type-Options', 'missing_xcto', 'medium'),
        ('X-Frame-Options', 'X-Frame-Options', 'missing_xfo', 'medium'),
        ('X-XSS-Protection', 'X-XSS-Protection', 'missing_xxss', 'low'),
        ('Referrer-Policy', 'Referrer-Policy', 'missing_referrer', 'low'),
        ('Permissions-Policy', 'Permissions-Policy', 'missing_permissions', 'low'),
    ]

    for header_name, display_name, vuln_key, severity in header_checks:
        results['total_checks'] += 1
        value = headers.get(header_name)
        passed = value is not None
        results['checks'].append({
            'name': display_name, 'passed': passed,
            'value': (value[:80] + '...' if value and len(value) > 80 else value) if passed else 'Отсутствует',
            'description': VULN_DATABASE[vuln_key]['description'][:100],
            'severity': severity,
        })
        if passed:
            results['passed_checks'] += 1
        else:
            results['vulnerabilities'].append(VULN_DATABASE[vuln_key])

    # SSL Certificate
    results['total_checks'] += 1
    ssl_result = check_ssl_cert(hostname)
    results['checks'].append(ssl_result['check'])
    if ssl_result['check']['passed']:
        results['passed_checks'] += 1
    if ssl_result.get('vuln'):
        results['vulnerabilities'].append(ssl_result['vuln'])

    # Server header
    results['total_checks'] += 1
    server = headers.get('Server')
    server_hidden = server is None
    results['checks'].append({
        'name': 'Server Header', 'passed': server_hidden,
        'value': 'Скрыт' if server_hidden else server,
        'description': 'Раскрытие информации о веб-сервере',
        'severity': 'info',
    })
    if server_hidden:
        results['passed_checks'] += 1
    else:
        results['vulnerabilities'].append(VULN_DATABASE['server_exposed'])

    # X-Powered-By
    results['total_checks'] += 1
    powered = headers.get('X-Powered-By')
    powered_hidden = powered is None
    results['checks'].append({
        'name': 'X-Powered-By', 'passed': powered_hidden,
        'value': 'Скрыт' if powered_hidden else powered,
        'description': 'Раскрытие используемого фреймворка',
        'severity': 'info',
    })
    if powered_hidden:
        results['passed_checks'] += 1
    else:
        results['vulnerabilities'].append(VULN_DATABASE['powered_by_exposed'])

    # Cookies
    results['total_checks'] += 1
    cookie_result = check_cookies(response)
    results['checks'].append(cookie_result['check'])
    if cookie_result['check']['passed']:
        results['passed_checks'] += 1
    if cookie_result.get('vuln'):
        results['vulnerabilities'].append(cookie_result['vuln'])

    # Redirect chain check
    results['total_checks'] += 1
    redirect_ok = len(response.history) <= 3
    results['checks'].append({
        'name': 'Цепочка редиректов', 'passed': redirect_ok,
        'value': f'{len(response.history)} редиректов' if response.history else 'Нет редиректов',
        'description': 'Проверка количества перенаправлений',
        'severity': 'low',
    })
    if redirect_ok:
        results['passed_checks'] += 1

    # Technology Detection
    results['technologies'] = detect_technologies(response)

    # Port Scan
    if results['ip_address']:
        results['open_ports'] = scan_ports(results['ip_address'])

    # Score
    total = results['total_checks']
    passed = results['passed_checks']
    results['score'] = round((passed / total) * 100) if total > 0 else 0

    results['scan_time'] = round(time.time() - start, 2)

    return results


def check_ssl_cert(hostname):
    result = {'check': None, 'vuln': None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.utcnow()).days
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', 'Unknown')

                if days_left > 30:
                    result['check'] = {
                        'name': 'SSL-сертификат', 'passed': True,
                        'value': f'{days_left} дней, {issuer_name}',
                        'description': f'Сертификат действителен, выдан: {issuer_name}',
                        'severity': 'critical',
                    }
                else:
                    result['check'] = {
                        'name': 'SSL-сертификат', 'passed': False,
                        'value': f'Истекает через {days_left} дней!',
                        'description': f'Сертификат скоро истечёт, выдан: {issuer_name}',
                        'severity': 'critical',
                    }
                    vuln = dict(VULN_DATABASE['ssl_expiring'])
                    vuln['description'] = f'Сертификат истекает через {days_left} дней ({not_after.strftime("%d.%m.%Y")})'
                    result['vuln'] = vuln
    except Exception as e:
        result['check'] = {
            'name': 'SSL-сертификат', 'passed': False,
            'value': f'Ошибка: {str(e)[:60]}',
            'description': 'Не удалось проверить SSL-сертификат',
            'severity': 'critical',
        }
        result['vuln'] = VULN_DATABASE['ssl_invalid']
    return result


def check_cookies(response):
    result = {'check': None, 'vuln': None}
    cookies = response.cookies
    if not cookies:
        result['check'] = {
            'name': 'Cookie Security', 'passed': True,
            'value': 'Cookie не обнаружены',
            'description': 'Проверка флагов безопасности Cookie',
            'severity': 'medium',
        }
        return result

    issues = []
    for cookie in cookies:
        if not cookie.secure:
            issues.append(f'{cookie.name}: нет Secure')
        if 'httponly' not in str(cookie._rest).lower():
            issues.append(f'{cookie.name}: нет HttpOnly')

    passed = len(issues) == 0
    result['check'] = {
        'name': 'Cookie Security', 'passed': passed,
        'value': 'Все флаги установлены' if passed else '; '.join(issues[:3]),
        'description': 'Проверка флагов Secure, HttpOnly, SameSite',
        'severity': 'medium',
    }
    if not passed:
        result['vuln'] = VULN_DATABASE['cookie_insecure']
    return result
