"""
Wyze Cloud API client for CamControl.

Auth + device discovery via wyze-sdk.
PTZ control via native TUTK protocol (wyzecam library) or docker-wyze-bridge fallback.

TUTK PTZ commands (from docker-wyze-bridge source):
  K10058: rotary_degree — horizontal(int16) + vertical(int16)
  K10060: rotary_action — horizontal(uint8) + vertical(uint8) + speed(uint8)
  K10064: ptz_position  — vertical(uint16) + horizontal(uint16)
"""

import logging
import struct
import threading
import time
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Wyze Pan camera model identifiers
WYZE_PTZ_MODELS = {"pan", "hl_pan", "hl_pan2", "hl_pan3", "wyzecp1"}


@dataclass
class WyzeCamera:
    """A camera discovered through the Wyze cloud API."""
    device_id: str       # MAC address
    name: str = ""
    model: str = ""
    has_ptz: bool = False
    state: str = "unknown"
    ip: str = ""
    p2p_id: str = ""       # TUTK P2P identifier
    enr: str = ""          # enrollment key for TUTK auth
    firmware: str = ""
    bridge_name: str = ""  # URL-safe name for wyze-bridge API
    product_model: str = ""
    properties: dict = field(default_factory=dict)

    def __str__(self):
        ptz = " [PTZ]" if self.has_ptz else ""
        status = f" ({self.state})" if self.state != "online" else ""
        return f"{self.name or self.model}{ptz}{status} ({self.device_id})"


class WyzeCloudAPI:
    """
    Wyze camera API client.

    Uses wyze-sdk for authentication and device discovery.
    PTZ via native TUTK protocol (preferred) or docker-wyze-bridge REST API fallback.
    """

    def __init__(self, bridge_url: str = "http://localhost:5151"):
        self.cameras: dict[str, WyzeCamera] = {}
        self._client = None  # wyze_sdk.Client
        self._bridge_url = bridge_url.rstrip("/")
        self._bridge_host = urlparse(bridge_url).hostname or "localhost"
        self.authenticated = False

        # TUTK native control
        self._tutk_sessions: dict[str, object] = {}  # camera_id → WyzeIOTCSession
        self._tutk_available = False
        try:
            from wyzecam import WyzeIOTC
            self._tutk_available = True
        except ImportError:
            pass

        # wyzecam auth info (needed for TUTK sessions)
        self._wyze_account = None
        self._wyze_cameras_raw = []  # raw WyzeCamera objects from wyzecam

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
            logger.error("Create one at: https://developer-api-console.wyze.com/")
            return False

        try:
            kwargs = {"email": email, "password": password,
                      "key_id": key_id, "api_key": api_key}
            logger.info("Authenticating with Wyze...")

            self._client = Client(**kwargs)
            self.authenticated = True
            logger.info("Wyze authentication successful")

            # Also auth with wyzecam library for TUTK sessions
            if self._tutk_available:
                self._init_wyzecam_auth(email, password)

            return True

        except Exception as e:
            logger.error(f"Wyze login failed: {e}")
            return False

    def _init_wyzecam_auth(self, email: str, password: str):
        """Initialize wyzecam library auth for native TUTK control."""
        try:
            import wyzecam
            cred = wyzecam.login(email, password)
            self._wyze_account = wyzecam.get_user_info(cred)
            self._wyze_cameras_raw = wyzecam.get_camera_list(cred)
            logger.info(f"wyzecam: authenticated, {len(self._wyze_cameras_raw)} cameras")
        except Exception as e:
            logger.warning(f"wyzecam auth failed (TUTK PTZ unavailable): {e}")
            self._wyze_account = None

    def login_with_bridge(self) -> bool:
        """Skip wyze-sdk auth — use bridge for everything."""
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
        """Discover cameras. Prefers bridge (has live state), falls back to SDK."""
        self.cameras.clear()
        if self.check_bridge() and self._get_devices_bridge():
            # Enrich with TUTK info from wyzecam if available
            self._enrich_with_tutk_info()
            return True
        if self._client:
            return self._get_devices_sdk()
        return False

    def _enrich_with_tutk_info(self):
        """Add P2P IDs and enrollment keys from wyzecam to bridge-discovered cameras."""
        if not self._wyze_cameras_raw:
            return
        for raw_cam in self._wyze_cameras_raw:
            mac = getattr(raw_cam, "mac", "")
            if mac in self.cameras:
                self.cameras[mac].p2p_id = getattr(raw_cam, "p2p_id", "")
                self.cameras[mac].enr = getattr(raw_cam, "enr", "")
                self.cameras[mac].product_model = getattr(raw_cam, "product_model", "")

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

            is_ptz = any(m in model_name.lower() for m in ("pan", "hl_pan"))
            bridge_name = self._to_bridge_name(nickname)

            self.cameras[mac] = WyzeCamera(
                device_id=mac, name=nickname, model=model_name,
                has_ptz=is_ptz, state="online" if is_online else "offline",
                ip=ip, bridge_name=bridge_name,
            )
            logger.info(f"Camera: {nickname} ({'PTZ' if is_ptz else 'fixed'}) — {model_name} ({mac})")

        self._enrich_with_tutk_info()
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
            cameras = data.get("cameras", data)
            if not isinstance(cameras, dict):
                return False

            for name_uri, info in cameras.items():
                if not isinstance(info, dict):
                    continue
                mac = info.get("mac", name_uri)
                model = info.get("model_name", info.get("product_model", ""))
                nickname = info.get("nickname", name_uri).strip()
                is_ptz = any(m in model.lower() for m in ("pan", "hl_pan"))

                self.cameras[mac] = WyzeCamera(
                    device_id=mac, name=nickname, model=model,
                    has_ptz=is_ptz, state="online",
                    ip=info.get("ip", ""),
                    bridge_name=info.get("name_uri", name_uri),
                    product_model=info.get("product_model", ""),
                )
                logger.info(f"Camera (bridge): {nickname} — {model} ({mac})")

            logger.info(f"Found {len(self.cameras)} cameras via bridge")
            return len(self.cameras) > 0

        except Exception as e:
            logger.error(f"Bridge device discovery failed: {e}")
            return False

    # === PTZ Control ===

    def move(self, camera_id: str, pan: float = 0.0, tilt: float = 0.0,
             zoom: float = 0.0, **kwargs) -> bool:
        """Relative move. Tries native TUTK first, falls back to bridge."""
        cam = self.cameras.get(camera_id)
        if not cam:
            logger.error(f"Camera {camera_id} not found")
            return False

        # Convert normalized step to degrees (0.05 step → ~5 degrees)
        horizontal = int(pan * 100)
        vertical = int(-tilt * 100)  # Wyze: positive = down

        # Try native TUTK
        if self._tutk_send_ptz(cam, 10058, struct.pack("<hh", horizontal, vertical)):
            return True

        # Fall back to bridge
        return self._bridge_cmd(cam.bridge_name, "rotary_degree", {
            "horizontal": str(horizontal),
            "vertical": str(vertical),
        })

    def move_to(self, camera_id: str, pan: float, tilt: float,
                zoom: float = 0.0, **kwargs) -> bool:
        """Absolute move."""
        cam = self.cameras.get(camera_id)
        if not cam:
            return False

        horizontal = int(pan * 350)
        vertical = int((1.0 - tilt) * 180)

        if self._tutk_send_ptz(cam, 10064, struct.pack("<HH", vertical, horizontal)):
            return True

        return self._bridge_cmd(cam.bridge_name, "ptz_position", {
            "horizontal": str(horizontal),
            "vertical": str(vertical),
        })

    def stop_move(self, camera_id: str) -> bool:
        cam = self.cameras.get(camera_id)
        if not cam:
            return False

        # rotary_action with 0,0,0 = stop
        if self._tutk_send_ptz(cam, 10060, struct.pack("<BBB", 0, 0, 1)):
            return True

        return self._bridge_cmd(cam.bridge_name, "rotary_action", {
            "horizontal": "0", "vertical": "0",
        })

    def go_home(self, camera_id: str) -> bool:
        cam = self.cameras.get(camera_id)
        if not cam:
            return False

        if self._tutk_send_ptz(cam, 10064, struct.pack("<HH", 90, 0)):
            return True

        return self._bridge_cmd(cam.bridge_name, "ptz_position", {
            "horizontal": "0", "vertical": "90",
        })

    # === Native TUTK PTZ ===

    def _tutk_send_ptz(self, cam: WyzeCamera, command_code: int, data: bytes) -> bool:
        """Send a PTZ command via native TUTK. Returns False if unavailable."""
        if not self._tutk_available or not self._wyze_account:
            return False
        if not cam.p2p_id or not cam.enr:
            return False

        session = self._get_tutk_session(cam)
        if not session:
            return False

        try:
            from wyzecam.tutk.tutk_protocol import encode
            msg = encode(command_code, len(data), data)
            session.iotctrl_mux().send_ioctl(msg)
            logger.debug(f"TUTK: sent command {command_code} to {cam.name}")
            return True
        except Exception as e:
            logger.warning(f"TUTK PTZ failed for {cam.name}: {e}")
            # Clean up dead session
            self._tutk_sessions.pop(cam.device_id, None)
            return False

    def _get_tutk_session(self, cam: WyzeCamera):
        """Get or create a TUTK session to a camera."""
        if cam.device_id in self._tutk_sessions:
            session = self._tutk_sessions[cam.device_id]
            try:
                session.session_check()
                return session
            except Exception:
                self._tutk_sessions.pop(cam.device_id, None)

        try:
            from wyzecam import WyzeIOTC
            # Find raw camera object
            raw_cam = None
            for rc in self._wyze_cameras_raw:
                if getattr(rc, "mac", "") == cam.device_id:
                    raw_cam = rc
                    break
            if not raw_cam:
                return None

            logger.info(f"TUTK: connecting to {cam.name}...")
            with WyzeIOTC() as wyze_iotc:
                session = wyze_iotc.connect_and_auth(self._wyze_account, raw_cam)
                self._tutk_sessions[cam.device_id] = session
                logger.info(f"TUTK: connected to {cam.name}")
                return session
        except Exception as e:
            logger.warning(f"TUTK: failed to connect to {cam.name}: {e}")
            return None

    # === Camera Settings ===

    def toggle_night_vision(self, camera_id: str, enabled: bool) -> bool:
        cam = self.cameras.get(camera_id)
        if not cam:
            return False
        mode = "3" if enabled else "1"
        return self._bridge_cmd(cam.bridge_name, "irled", {"value": mode})

    def toggle_privacy(self, camera_id: str, enabled: bool) -> bool:
        if not self._client:
            return False
        try:
            cam = self.cameras.get(camera_id)
            if not cam:
                return False
            if enabled:
                self._client.cameras.turn_off(device_mac=camera_id,
                                               device_model=cam.product_model or cam.model)
            else:
                self._client.cameras.turn_on(device_mac=camera_id,
                                              device_model=cam.product_model or cam.model)
            return True
        except Exception as e:
            logger.error(f"Failed to toggle camera: {e}")
            return False

    def trigger_snapshot(self, camera_id: str) -> Optional[str]:
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

        # Tell bridge to start the stream
        self._bridge_cmd(cam.bridge_name, "start")

        url = f"rtsp://{self._bridge_host}:8554/{cam.bridge_name}"
        logger.info(f"Stream URL: {url}")
        return url

    def start_event_stream(self):
        pass

    def on_event(self, callback):
        pass

    def close(self):
        for session in self._tutk_sessions.values():
            try:
                session.close() if hasattr(session, 'close') else None
            except Exception:
                pass
        self._tutk_sessions.clear()
        self._client = None
        self.authenticated = False

    # === Bridge HTTP Helpers ===

    def _bridge_cmd(self, cam_name: str, command: str,
                    params: dict = None) -> bool:
        """Send a command to a camera via the wyze-bridge REST API."""
        url = f"{self._bridge_url}/api/{cam_name}/{command}"
        try:
            resp = requests.get(url, params=params or {}, timeout=60)
            if resp.status_code == 200:
                data = resp.json() if resp.text else {}
                if isinstance(data, dict) and data.get("status") == "error":
                    logger.warning(f"Bridge: {command} → {cam_name}: {data.get('response', 'error')}")
                    return False
                logger.debug(f"Bridge: {command} → {cam_name} OK")
                return True
            else:
                logger.warning(f"Bridge: {command} → {cam_name} HTTP {resp.status_code}")
                return False
        except requests.ReadTimeout:
            logger.warning(f"Bridge: {command} → {cam_name} timed out")
            return False
        except requests.ConnectionError:
            logger.error(f"Cannot connect to wyze-bridge at {self._bridge_url}")
            return False

    def _to_bridge_name(self, nickname: str) -> str:
        return nickname.lower().replace(" ", "-").replace("'", "")

    def check_bridge(self) -> bool:
        try:
            resp = requests.get(f"{self._bridge_url}/api", timeout=3)
            return resp.status_code == 200
        except (requests.ConnectionError, requests.ReadTimeout):
            return False
