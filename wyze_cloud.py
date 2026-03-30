"""
Wyze Cloud API client for CamControl.

Auth + device discovery via wyze-sdk.
PTZ control via Wyze cloud run_action API — no Docker or TUTK needed.

The wyze-sdk has no PTZ methods, but its internal ApiServiceClient exposes
run_action() which sends commands through Wyze's cloud to the camera.

PTZ action keys (discovered via reverse-engineering):
  pan_left, pan_right, tilt_up, tilt_down, reset_rotation
"""

import logging
import time
from typing import Optional
from dataclasses import dataclass, field

import requests

logger = logging.getLogger(__name__)


@dataclass
class WyzeCamera:
    """A camera discovered through the Wyze cloud API."""
    device_id: str       # MAC address
    name: str = ""
    model: str = ""
    product_model: str = ""
    has_ptz: bool = False
    state: str = "unknown"
    ip: str = ""
    firmware: str = ""
    properties: dict = field(default_factory=dict)

    def __str__(self):
        ptz = " [PTZ]" if self.has_ptz else ""
        status = f" ({self.state})" if self.state != "online" else ""
        return f"{self.name or self.model}{ptz}{status} ({self.device_id})"


class WyzeCloudAPI:
    """
    Wyze camera API client.

    Uses wyze-sdk for authentication and device discovery.
    PTZ via Wyze cloud run_action API (no Docker/TUTK needed).

    Flow:
    1. login(email, password, key_id, api_key) → authenticate via wyze-sdk
    2. get_devices() → list cameras via wyze-sdk
    3. move/stop/home → run_action calls through Wyze cloud
    """

    def __init__(self, bridge_url: str = "http://localhost:5151"):
        self.cameras: dict[str, WyzeCamera] = {}
        self._client = None  # wyze_sdk.Client
        self._api = None      # wyze_sdk ApiServiceClient (for run_action)
        self._bridge_url = bridge_url.rstrip("/")
        self.authenticated = False

    def login(self, email: str, password: str,
              key_id: str = "", api_key: str = "") -> bool:
        """Authenticate with Wyze via wyze-sdk."""
        try:
            from wyze_sdk import Client
        except ImportError:
            logger.error("wyze-sdk not installed. Run: pip install wyze-sdk")
            return False

        if not key_id or not api_key:
            logger.error("Wyze API key and key ID are required (since July 2023).")
            return False

        try:
            self._client = Client(email=email, password=password,
                                  key_id=key_id, api_key=api_key)
            # Get the internal API client for run_action
            self._api = self._client.cameras._api_client()
            self.authenticated = True
            logger.info("Wyze authentication successful")
            return True
        except Exception as e:
            logger.error(f"Wyze login failed: {e}")
            return False

    def login_with_bridge(self) -> bool:
        """Use bridge for device discovery (PTZ still needs wyze-sdk auth)."""
        try:
            resp = requests.get(f"{self._bridge_url}/api", timeout=5)
            if resp.status_code == 200:
                self.authenticated = True
                logger.info("Connected to wyze-bridge API")
                return True
        except requests.ConnectionError:
            pass
        return False

    def get_devices(self) -> bool:
        """Discover cameras via wyze-sdk."""
        self.cameras.clear()
        if self._client:
            return self._get_devices_sdk()
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
            product_model = ""
            if hasattr(cam, "product") and cam.product:
                model_name = getattr(cam.product, "model", "")
                product_model = model_name

            nickname = getattr(cam, "nickname", "") or ""
            mac = getattr(cam, "mac", "") or ""
            is_online = getattr(cam, "is_online", False)
            ip = getattr(cam, "ip", "") or ""
            fw = getattr(cam, "firmware_version", "") or ""

            is_ptz = any(m in model_name.lower() for m in ("pan", "hl_pan"))

            self.cameras[mac] = WyzeCamera(
                device_id=mac, name=nickname, model=model_name,
                product_model=product_model,
                has_ptz=is_ptz,
                state="online" if is_online else "offline",
                ip=ip, firmware=fw,
            )
            logger.info(f"Camera: {nickname} ({'PTZ' if is_ptz else 'fixed'}) — {model_name} ({mac})")

        logger.info(f"Found {len(self.cameras)} Wyze cameras")
        return True

    # === PTZ Control (via Wyze cloud run_action API) ===

    def move(self, camera_id: str, pan: float = 0.0, tilt: float = 0.0,
             zoom: float = 0.0, **kwargs) -> bool:
        """Move camera using Wyze cloud API.

        Each call sends one step in the given direction.
        pan > 0 = right, pan < 0 = left
        tilt > 0 = up, tilt < 0 = down
        """
        cam = self.cameras.get(camera_id)
        if not cam:
            logger.error(f"Camera {camera_id} not found")
            return False

        success = True
        if pan > 0:
            success = self._run_action(cam, "pan_right")
        elif pan < 0:
            success = self._run_action(cam, "pan_left")

        if tilt > 0:
            success = self._run_action(cam, "tilt_up") and success
        elif tilt < 0:
            success = self._run_action(cam, "tilt_down") and success

        return success

    def move_to(self, camera_id: str, pan: float, tilt: float,
                zoom: float = 0.0, **kwargs) -> bool:
        """Absolute move not supported via cloud API — use reset + relative."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        # Best we can do: reset to home first
        self._run_action(cam, "reset_rotation")
        return True

    def stop_move(self, camera_id: str) -> bool:
        """Stop not needed — each cloud action is a single step."""
        return True

    def go_home(self, camera_id: str) -> bool:
        """Reset camera to home position."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        return self._run_action(cam, "reset_rotation")

    def _run_action(self, cam: WyzeCamera, action_key: str,
                    action_params: dict = None) -> bool:
        """Send a command to a camera via Wyze cloud run_action API."""
        if not self._api:
            logger.error("Not authenticated — cannot send PTZ commands")
            return False

        provider_key = cam.product_model or cam.model
        try:
            resp = self._api.run_action(
                mac=cam.device_id,
                action_key=action_key,
                action_params=action_params or {},
                provider_key=provider_key,
            )
            result = resp.get("data", {}).get("result", -1)
            if result == 3:
                logger.debug(f"PTZ: {action_key} → {cam.name} (queued)")
                return True
            elif result == 1:
                logger.debug(f"PTZ: {action_key} → {cam.name} (success)")
                return True
            else:
                logger.warning(f"PTZ: {action_key} → {cam.name} result={result}")
                return False
        except Exception as e:
            logger.error(f"PTZ failed: {action_key} → {cam.name}: {e}")
            return False

    # === Camera Settings ===

    def toggle_night_vision(self, camera_id: str, enabled: bool) -> bool:
        """Toggle night vision via device property."""
        if not self._api:
            return False
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        try:
            # P1001 = night vision: 1=on, 2=off, 3=auto
            self._api.set_device_property(
                mac=camera_id, model=cam.product_model or cam.model,
                pid="P1001", value="1" if enabled else "2",
            )
            return True
        except Exception as e:
            logger.error(f"Night vision toggle failed: {e}")
            return False

    def toggle_privacy(self, camera_id: str, enabled: bool) -> bool:
        """Turn camera on/off."""
        if not self._client:
            return False
        try:
            cam = self.cameras.get(camera_id)
            if not cam:
                return False
            model = cam.product_model or cam.model
            if enabled:
                self._client.cameras.turn_off(device_mac=camera_id, device_model=model)
            else:
                self._client.cameras.turn_on(device_mac=camera_id, device_model=model)
            return True
        except Exception as e:
            logger.error(f"Failed to toggle camera: {e}")
            return False

    def trigger_snapshot(self, camera_id: str) -> Optional[str]:
        """Snapshots require TUTK/bridge — not available via cloud API."""
        return None

    # === Streaming ===

    def start_stream(self, camera_id: str) -> Optional[str]:
        """Return RTSP URL if docker-wyze-bridge is running, else None.

        Streaming requires the bridge (TUTK). PTZ works without it.
        """
        cam = self.cameras.get(camera_id)
        if not cam:
            return None

        # Check if bridge is available for streaming
        if self.check_bridge():
            bridge_name = cam.name.lower().replace(" ", "-").replace("'", "")
            # Tell bridge to start this camera's stream
            try:
                requests.get(f"{self._bridge_url}/api/{bridge_name}/start", timeout=5)
            except Exception:
                pass
            url = f"rtsp://localhost:8554/{bridge_name}"
            logger.info(f"Stream URL (bridge): {url}")
            return url

        logger.info("No bridge available — streaming requires docker-wyze-bridge")
        return None

    def start_event_stream(self):
        pass

    def on_event(self, callback):
        pass

    def close(self):
        self._client = None
        self._api = None
        self.authenticated = False

    def check_bridge(self) -> bool:
        """Check if docker-wyze-bridge is reachable (optional, for streaming)."""
        try:
            resp = requests.get(f"{self._bridge_url}/api", timeout=2)
            return resp.status_code == 200
        except (requests.ConnectionError, requests.ReadTimeout):
            return False
