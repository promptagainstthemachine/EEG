"""WebSocket consumers for real-time security updates."""

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from apps.accounts.models import Organization


@database_sync_to_async
def _org_live_monitoring_allowed(org_id: int) -> bool:
    row = (
        Organization.objects.filter(pk=org_id)
        .only("realtime_monitoring_enabled")
        .first()
    )
    return bool(row and row.realtime_monitoring_enabled)


class SecurityLiveConsumer(AsyncJsonWebsocketConsumer):
    """WebSocket consumer for real-time security findings and alerts."""

    async def connect(self):
        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close()
            return

        org = getattr(user, "organization", None)
        if not org:
            await self.close()
            return

        if not await _org_live_monitoring_allowed(org.id):
            await self.close()
            return

        self.org_id = org.id
        self.group_name = f"security_{self.org_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content):
        pass

    async def security_finding(self, event):
        await self.send_json(
            {
                "type": "finding",
                "data": event["data"],
            }
        )

    async def scan_progress(self, event):
        await self.send_json(
            {
                "type": "scan_progress",
                "data": event["data"],
            }
        )

    async def alert(self, event):
        await self.send_json(
            {
                "type": "alert",
                "data": event["data"],
            }
        )
