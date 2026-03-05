from django.db import models
import json


class ScanResult(models.Model):
    url = models.URLField(max_length=500)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    score = models.IntegerField(default=0)
    total_checks = models.IntegerField(default=0)
    passed_checks = models.IntegerField(default=0)
    results_json = models.JSONField(default=dict)
    technologies = models.JSONField(default=list)
    open_ports = models.JSONField(default=list)
    scanned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-scanned_at']

    def __str__(self):
        return f"{self.url} — {self.score}/100"

    @property
    def grade(self):
        if self.score >= 90: return 'A+'
        if self.score >= 80: return 'A'
        if self.score >= 70: return 'B'
        if self.score >= 55: return 'C'
        if self.score >= 40: return 'D'
        return 'F'

    @property
    def grade_color(self):
        g = self.grade
        if g in ('A+', 'A'): return '#00ff88'
        if g == 'B': return '#88ff00'
        if g == 'C': return '#ffcc00'
        if g == 'D': return '#ff8800'
        return '#ff3355'

    @property
    def risk_level(self):
        if self.score >= 80: return 'Низкий'
        if self.score >= 55: return 'Средний'
        if self.score >= 30: return 'Высокий'
        return 'Критический'
