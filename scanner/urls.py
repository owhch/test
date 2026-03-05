from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('api/scan/', views.scan_api, name='scan_api'),
    path('history/', views.history, name='history'),
]
