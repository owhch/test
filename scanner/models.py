from django.db import models


class ScanResult(models.Model):
    url = models.URLField(max_length=500)
    score = models.IntegerField(default=0)
    total_checks = models.IntegerField(default=0)
    passed_checks = models.IntegerField(default=0)
    results_json = models.JSONField(default=dict)
    scanned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-scanned_at']

    def __str__(self):
        return f"{self.url} — {self.score}/100"

    @property
    def grade(self):
        if self.score >= 90:
            return 'A'
        elif self.score >= 75:
            return 'B'
        elif self.score >= 60:
            return 'C'
        elif self.score >= 40:
            return 'D'
        return 'F'

    @property
    def grade_color(self):
        colors = {'A': '#00ff88', 'B': '#88ff00', 'C': '#ffcc00', 'D': '#ff8800', 'F': '#ff3355'}
        return colors.get(self.grade, '#ff3355')
