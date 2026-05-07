from abc import ABC, abstractmethod
from typing import Any


class BaseAdapter(ABC):
    def __init__(self, hostname: str, credentials: dict):
        self.hostname = hostname
        self.credentials = credentials

    @abstractmethod
    def get_supported_cache_keys(self) -> list[str]:
        """Return the list of cache keys this adapter can populate."""

    @abstractmethod
    async def fetch(self, cache_key: str) -> Any:
        """Fetch fresh data for the given cache key."""

    @abstractmethod
    async def execute_action(self, action: dict) -> dict:
        """Execute a device action. action dict must contain 'type'."""

    async def close(self) -> None:
        """Release any per-instance resources (e.g. open Redfish sessions).
        Called by the poller after a fetch cycle. Default no-op."""
