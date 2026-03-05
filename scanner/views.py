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
        scan = ScanResult.objects.create(
            url=results['url'],
            score=results['score'],
            total_checks=results['total_checks'],
            passed_checks=results['passed_checks'],
            results_json=results,
        )

    return JsonResponse(results)


def history(request):
    scans = ScanResult.objects.all()[:50]
    return render(request, 'scanner/history.html', {'scans': scans})
