from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('url', 'score', 'grade', 'ip_address', 'scanned_at')
    list_filter = ('scanned_at',)
    search_fields = ('url',)
