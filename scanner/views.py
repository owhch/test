import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ScanResult
from .utils import analyze_url


def index(request):
    recent_scans = ScanResult.objects.all()[:10]
    return render(request, 'scanner/index.html', {'recent_scans': recent_scans})


@csrf_exempt
def scan_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    try:
        data = json.loads(request.body)
        url = data.get('url', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    if not url:
        return JsonResponse({'error': 'URL is required'}, status=400)

    results = analyze_url(url)

    if 'error' not in results:
        ScanResult.objects.create(
            url=results['url'],
            ip_address=results.get('ip_address'),
            score=results['score'],
            total_checks=results['total_checks'],
            passed_checks=results['passed_checks'],
            results_json=results,
            technologies=results.get('technologies', []),
            open_ports=results.get('open_ports', []),
        )

    return JsonResponse(results)


def history(request):
    scans = ScanResult.objects.all()[:50]
    return render(request, 'scanner/history.html', {'scans': scans})


def stats_api(request):
    total = ScanResult.objects.count()
    if total == 0:
        return JsonResponse({'total': 0, 'avg_score': 0})
    from django.db.models import Avg
    avg = ScanResult.objects.aggregate(Avg('score'))['score__avg'] or 0
    return JsonResponse({'total': total, 'avg_score': round(avg, 1)})
