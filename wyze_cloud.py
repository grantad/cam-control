"""
Wyze Cloud API client for CamControl.

Auth + device discovery via wyze-sdk.
PTZ control + streaming via docker-wyze-bridge REST API.

The wyze-sdk has no PTZ methods — it only handles auth, camera listing,
and basic on/off. All PTZ commands go through the wyze-bridge REST API
which talks to cameras via the TUTK protocol.

Bridge API reference (mrlt8/docker-wyze-bridge):
  GET /api/{cam_name}/rotary_degree?horizontal=N&vertical=N  — relative move
  GET /api/{cam_name}/rotary_action?horizontal=0|1|2&vertical=0|1|2  — continuous
  GET /api/{cam_name}/ptz_position?vertical=N&horizontal=N  — absolute position
  GET /api/{cam_name}/cruise_points  — get waypoints
  GET /api/{cam_name}/state  — camera state
"""

import logging
import time
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Wyze Pan camera model identifiers
WYZE_PTZ_MODELS = {
    "wyze cam pan",
    "wyze cam pan v2",
    "wyze cam pan v3",
    "pan cam",
    "hl_panv2",       # hardware model for Pan v2
    "hl_pan3",        # hardware model for Pan v3
    "wyzecp1",        # product model Pan v1
    "hl_pan2",
}


@dataclass
class WyzeCamera:
    """A camera discovered through the Wyze cloud API."""
    device_id: str       # MAC address
    name: str = ""
    model: str = ""
    has_ptz: bool = False
    state: str = "unknown"
    ip: str = ""
    firmware: str = ""
    bridge_name: str = ""  # URL-safe name for wyze-bridge API
    properties: dict = field(default_factory=dict)

    def __str__(self):
        ptz = " [PTZ]" if self.has_ptz else ""
        status = f" ({self.state})" if self.state != "online" else ""
        return f"{self.name or self.model}{ptz}{status} ({self.device_id})"


class WyzeCloudAPI:
    """
    Wyze camera API client.

    Uses wyze-sdk for authentication and device discovery.
    Uses docker-wyze-bridge REST API for PTZ control and streaming.

    Flow:
    1. login(email, password) → authenticate via wyze-sdk
    2. get_devices() → list cameras via wyze-sdk
    3. move/stop/home → REST calls to docker-wyze-bridge
    4. start_stream() → RTSP URL from docker-wyze-bridge
    """

    def __init__(self, bridge_url: str = "http://localhost:5000"):
        self.cameras: dict[str, WyzeCamera] = {}
        self._client = None  # wyze_sdk.Client
        self._bridge_url = bridge_url.rstrip("/")
        self._bridge_host = urlparse(bridge_url).hostname or "localhost"
        self.authenticated = False

    def login(self, email: str, password: str,
              key_id: str = "", api_key: str = "") -> bool:
        """Authenticate with Wyze via wyze-sdk."""
        try:
            from wyze_sdk import Client
        except ImportError:
            logger.error("wyze-sdk not installed. Run: pip install wyze-sdk")
            return False

        try:
            kwargs = {"email": email, "password": password}
            if key_id and api_key:
                kwargs["key_id"] = key_id
                kwargs["api_key"] = api_key
                logger.info("Authenticating with Wyze (API key method)...")
            else:
                logger.info("Authenticating with Wyze (email/password)...")

            self._client = Client(**kwargs)
            self.authenticated = True
            logger.info("Wyze authentication successful")
            return True

        except Exception as e:
            logger.error(f"Wyze login failed: {e}")
            return False

    def login_with_bridge(self) -> bool:
        """Skip wyze-sdk auth entirely — use bridge for everything.

        If the bridge is running and has cameras, we can discover
        them via the bridge API without needing wyze-sdk credentials.
        """
        try:
            resp = requests.get(f"{self._bridge_url}/api", timeout=5)
            if resp.status_code == 200:
                self.authenticated = True
                logger.info("Connected to wyze-bridge API")
                return True
        except requests.ConnectionError:
            logger.error(f"Cannot connect to wyze-bridge at {self._bridge_url}")
        return False

    def get_devices(self) -> bool:
        """Discover cameras. Tries wyze-sdk first, falls back to bridge API."""
        # Try wyze-sdk
        if self._client:
            return self._get_devices_sdk()
        # Fall back to bridge API
        if self.authenticated:
            return self._get_devices_bridge()
        return False

    def _get_devices_sdk(self) -> bool:
        """List cameras via wyze-sdk."""
        try:
            cams = self._client.cameras.list()
        except Exception as e:
            logger.error(f"Failed to list Wyze cameras: {e}")
            return False

        for cam in cams:
            model_name = ""
            if hasattr(cam, "product") and cam.product:
                model_name = getattr(cam.product, "model", "")

            nickname = getattr(cam, "nickname", "") or ""
            mac = getattr(cam, "mac", "") or ""
            is_online = getattr(cam, "is_online", False)
            ip = getattr(cam, "ip", "") or ""
            fw = getattr(cam, "firmware_version", "") or ""

            # Detect PTZ capability from model name
            is_ptz = any(
                m in model_name.lower()
                for m in ("pan", "hl_pan")
            )

            bridge_name = self._to_bridge_name(nickname)

            self.cameras[mac] = WyzeCamera(
                device_id=mac,
                name=nickname,
                model=model_name,
                has_ptz=is_ptz,
                state="online" if is_online else "offline",
                ip=ip,
                firmware=fw,
                bridge_name=bridge_name,
            )
            logger.info(f"Camera: {nickname} ({'PTZ' if is_ptz else 'fixed'}) — {model_name} ({mac})")

        logger.info(f"Found {len(self.cameras)} Wyze cameras")
        return True

    def _get_devices_bridge(self) -> bool:
        """List cameras via wyze-bridge REST API."""
        try:
            resp = requests.get(f"{self._bridge_url}/api", timeout=10)
            if resp.status_code != 200:
                logger.error(f"Bridge API returned {resp.status_code}")
                return False

            data = resp.json()
            # Bridge returns dict of camera name → info
            if isinstance(data, dict):
                for name, info in data.items():
                    if not isinstance(info, dict):
                        continue
                    mac = info.get("mac", name)
                    model = info.get("model_name", info.get("product_model", ""))
                    is_ptz = any(m in model.lower() for m in ("pan", "hl_pan"))
                    status = info.get("status", "unknown")

                    self.cameras[mac] = WyzeCamera(
                        device_id=mac,
                        name=info.get("nickname", name),
                        model=model,
                        has_ptz=is_ptz,
                        state="online" if status == "connected" else status,
                        bridge_name=name,
                    )
                    logger.info(f"Camera (bridge): {name} — {model} ({mac})")

            logger.info(f"Found {len(self.cameras)} cameras via bridge")
            return True

        except Exception as e:
            logger.error(f"Bridge device discovery failed: {e}")
            return False

    # === PTZ Control (via docker-wyze-bridge REST API) ===

    def move(self, camera_id: str, pan: float = 0.0, tilt: float = 0.0,
             zoom: float = 0.0, **kwargs) -> bool:
        """Relative move via bridge rotary_degree command.

        pan:  -1.0 (left) to 1.0 (right) — mapped to degrees
        tilt: -1.0 (down) to 1.0 (up) — mapped to degrees
        """
        cam = self.cameras.get(camera_id)
        if not cam:
            logger.error(f"Camera {camera_id} not found")
            return False

        # Convert normalized step to degrees (0.05 step → ~5 degrees)
        horizontal = int(pan * 100)   # 0.05 → 5 degrees
        vertical = int(-tilt * 100)   # Wyze: positive = down, Arlo: positive = up

        return self._bridge_cmd(cam.bridge_name, "rotary_degree", {
            "horizontal": str(horizontal),
            "vertical": str(vertical),
        })

    def move_to(self, camera_id: str, pan: float, tilt: float,
                zoom: float = 0.0, **kwargs) -> bool:
        """Absolute move via bridge ptz_position command.

        pan:  0.0 to 1.0 → mapped to 0-350 degrees horizontal
        tilt: 0.0 to 1.0 → mapped to 0-180 degrees vertical
        """
        cam = self.cameras.get(camera_id)
        if not cam:
            return False

        horizontal = int(pan * 350)
        vertical = int((1.0 - tilt) * 180)  # 0=top, 180=bottom

        return self._bridge_cmd(cam.bridge_name, "ptz_position", {
            "horizontal": str(horizontal),
            "vertical": str(vertical),
        })

    def stop_move(self, camera_id: str) -> bool:
        """Stop continuous movement."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        # rotary_action with 0,0 = stop
        return self._bridge_cmd(cam.bridge_name, "rotary_action", {
            "horizontal": "0",
            "vertical": "0",
        })

    def go_home(self, camera_id: str) -> bool:
        """Move to center position (roughly 0 horizontal, 90 vertical)."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        return self._bridge_cmd(cam.bridge_name, "ptz_position", {
            "horizontal": "0",
            "vertical": "90",
        })

    # === Camera Settings ===

    def toggle_night_vision(self, camera_id: str, enabled: bool) -> bool:
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        mode = "3" if enabled else "1"  # 1=off, 2=on, 3=auto
        return self._bridge_cmd(cam.bridge_name, "irled", {"value": mode})

    def toggle_privacy(self, camera_id: str, enabled: bool) -> bool:
        """Turn camera on/off (Wyze doesn't have a privacy shutter)."""
        if not self._client:
            return False
        try:
            if enabled:
                self._client.cameras.turn_off(device_mac=camera_id,
                                               device_model=self.cameras[camera_id].model)
            else:
                self._client.cameras.turn_on(device_mac=camera_id,
                                              device_model=self.cameras[camera_id].model)
            return True
        except Exception as e:
            logger.error(f"Failed to toggle camera: {e}")
            return False

    def trigger_snapshot(self, camera_id: str) -> Optional[str]:
        """Request a snapshot via bridge."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return None
        self._bridge_cmd(cam.bridge_name, "snapshot")
        return f"{self._bridge_url}/snapshot/{cam.bridge_name}.jpg"

    # === Streaming ===

    def start_stream(self, camera_id: str) -> Optional[str]:
        """Return RTSP URL from docker-wyze-bridge."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return None
        url = f"rtsp://{self._bridge_host}:8554/{cam.bridge_name}"
        logger.info(f"Stream URL: {url}")
        return url

    # === Event Stream (no-op for Wyze — bridge handles everything) ===

    def start_event_stream(self):
        pass

    def on_event(self, callback):
        pass

    # === Cleanup ===

    def close(self):
        self._client = None
        self.authenticated = False

    # === Bridge HTTP Helpers ===

    def _bridge_cmd(self, cam_name: str, command: str,
                    params: dict = None) -> bool:
        """Send a command to a camera via the wyze-bridge REST API."""
        url = f"{self._bridge_url}/api/{cam_name}/{command}"
        try:
            resp = requests.get(url, params=params or {}, timeout=10)
            if resp.status_code == 200:
                logger.debug(f"Bridge: {command} → {cam_name} OK")
                return True
            else:
                logger.warning(f"Bridge: {command} → {cam_name} HTTP {resp.status_code}: {resp.text[:100]}")
                return False
        except requests.ConnectionError:
            logger.error(f"Cannot connect to wyze-bridge at {self._bridge_url}")
            return False

    def _to_bridge_name(self, nickname: str) -> str:
        """Convert camera nickname to wyze-bridge URL-safe name."""
        return nickname.lower().replace(" ", "-").replace("'", "")

    def check_bridge(self) -> bool:
        """Check if docker-wyze-bridge is reachable."""
        try:
            resp = requests.get(f"{self._bridge_url}/api", timeout=3)
            return resp.status_code == 200
        except requests.ConnectionError:
            return False
