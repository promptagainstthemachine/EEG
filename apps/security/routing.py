"""WebSocket routing for EEG OSS security app."""
from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path("ws/security/live/", consumers.SecurityLiveConsumer.as_asgi()),
]
