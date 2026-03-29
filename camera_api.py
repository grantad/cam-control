"""
Shared camera API protocol for multi-brand support.

Defines the CameraInfo dataclass and CameraAPI protocol that both
ArloCloudAPI and WyzeCloudAPI satisfy via duck typing.
"""

from typing import Optional, Protocol, runtime_checkable
from dataclasses import dataclass, field


@dataclass
class CameraInfo:
    """Brand-agnostic camera representation."""
    device_id: str
    name: str = ""
    model: str = ""
    brand: str = ""        # "arlo", "wyze", etc.
    has_ptz: bool = False
    state: str = "unknown"
    properties: dict = field(default_factory=dict)

    def __str__(self):
        ptz = " [PTZ]" if self.has_ptz else ""
        return f"{self.name or self.model}{ptz} ({self.device_id})"


@runtime_checkable
class CameraAPI(Protocol):
    """Protocol that camera API clients must satisfy.

    ArloCloudAPI already satisfies this via duck typing (no changes needed).
    WyzeCloudAPI implements it explicitly.
    """

    cameras: dict

    def get_devices(self) -> bool: ...
    def start_event_stream(self) -> None: ...
    def move(self, camera_id: str, pan: float = 0.0, tilt: float = 0.0, zoom: float = 0.0, **kwargs) -> bool: ...
    def stop_move(self, camera_id: str) -> bool: ...
    def go_home(self, camera_id: str) -> bool: ...
    def start_stream(self, camera_id: str) -> Optional[str]: ...
    def toggle_night_vision(self, camera_id: str, enabled: bool) -> bool: ...
    def toggle_privacy(self, camera_id: str, enabled: bool) -> bool: ...
    def close(self) -> None: ...
