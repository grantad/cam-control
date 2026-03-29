"""
Arlo Cloud API client for direct-WiFi cameras (no base station).

Authenticates with Arlo's cloud, establishes an event stream (SSE/MQTT),
and sends PTZ + control commands through their infrastructure.

Bypasses the Arlo app — you control the camera from the CLI.

Auth flow reverse-engineered from pyaarlo (twrecked/pyaarlo).
"""

import base64
import json
import time
import logging
import threading
import uuid
import ssl
from typing import Optional, Any, Callable
from dataclasses import dataclass, field

import cloudscraper
import requests

logger = logging.getLogger(__name__)

# Correct Arlo API endpoints (from pyaarlo reverse engineering)
ARLO_URLS = {
    "base":       "https://myapi.arlo.com/hmsweb",
    "auth":       "https://ocapi-app.arlo.com/api",
    "mqtt_host":  "mqtt-cluster.arloxcld.com",
    "mqtt_port":  443,
}

# Known PTZ-capable Arlo models (direct WiFi)
PTZ_MODELS = {
    "vmc4040p", "vmc4041p", "vmc4050p", "vmc5040",
    "vmc4060p", "abc1000", "vmc2040", "vmc2040s",
    "vml4030", "vml2030", "vmc3060", "vmc3060s",
    "vmc2032", "vmc3052",
}


@dataclass
class ArloCloudCamera:
    """A camera discovered through the Arlo cloud API."""
    device_id: str
    parent_id: str = ""         # Base station ID or own ID for direct-WiFi
    unique_id: str = ""
    serial: str = ""
    model: str = ""
    name: str = ""
    firmware: str = ""
    has_ptz: bool = False
    state: str = "unknown"
    user_id: str = ""
    xcloud_id: str = ""
    properties: dict = field(default_factory=dict)

    def __str__(self):
        ptz = " [PTZ]" if self.has_ptz else ""
        return f"{self.name or self.model}{ptz} ({self.device_id})"


class ArloCloudAPI:
    """
    Cloud API client for Arlo cameras.

    Flow:
    1. Login with email + password (+ 2FA if enabled)
    2. Get device list and identify PTZ cameras
    3. Subscribe to event stream (SSE) for async responses
    4. Send PTZ commands through the notify endpoint
    """

    def __init__(self):
        # Use cloudscraper for auth endpoint (Cloudflare-protected)
        self._auth_session = cloudscraper.create_scraper()

        # Regular session for API calls
        self.session = requests.Session()

        # Device ID for this "client" — persisted across requests
        self._device_id = str(uuid.uuid4())

        # Auth headers (matching the Arlo iOS app)
        self._auth_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Content-Type": "application/json",
            "Origin": "https://my.arlo.com",
            "Pragma": "no-cache",
            "Referer": "https://my.arlo.com/",
            "Source": "arloCamWeb",
            "User-Agent": "(iPhone15,2 18_1_1) iOS Arlo 5.4.3",
            "X-User-Device-Automation-Name": "Q2FtQ29udHJvbA==",  # base64("CamControl")
            "X-User-Device-Id": self._device_id,
            "X-User-Device-Type": "BROWSER",
        }

        # API headers
        self._api_headers = {
            "Accept": "application/json",
            "Auth-Version": "2",
            "Content-Type": "application/json; charset=utf-8;",
            "Origin": "https://my.arlo.com",
            "Referer": "https://my.arlo.com/",
            "SchemaVersion": "1",
            "User-Agent": "(iPhone15,2 18_1_1) iOS Arlo 5.4.3",
        }

        self.session.headers.update(self._api_headers)

        self.authenticated = False
        self.user_id = ""
        self.token = ""
        self.web_id = ""

        # Devices
        self.cameras: dict[str, ArloCloudCamera] = {}
        self.base_stations: dict[str, dict] = {}

        # Event stream
        self._event_thread: Optional[threading.Thread] = None
        self._event_running = False
        self._trans_id = 0
        self._trans_lock = threading.Lock()
        self._pending: dict[str, threading.Event] = {}
        self._responses: dict[str, Any] = {}

        # Callbacks
        self._event_callbacks: list[Callable] = []

        # 2FA state
        self._factor_id = ""
        self._auth_token_partial = ""

    # === Authentication ===

    def login(self, email: str, password: str) -> bool:
        """
        Login to Arlo cloud. Returns True if successful.
        If 2FA is required, returns False and sets up state for verify_2fa().
        """
        logger.info("Logging in to Arlo cloud...")

        # Arlo expects the password base64-encoded
        password_b64 = base64.b64encode(password.encode()).decode()

        resp = self._auth_post(f"{ARLO_URLS['auth']}/auth", {
            "email": email,
            "password": password_b64,
            "language": "en",
            "EnvSource": "prod",
        })

        if not resp:
            return False

        data = resp.get("data", {})
        meta = resp.get("meta", {})
        code = meta.get("code", 0)

        if code == 200 and data.get("token"):
            # Direct success (no 2FA)
            return self._complete_auth(data)

        # 2FA required (code 200 with authenticated=false, or code 202)
        if data.get("authenticated") is False or code == 202:
            self._auth_token_partial = data.get("token", "")
            self._factor_id = data.get("factorAuthId", "")

            # If no factorAuthId, we need to get factors and start auth
            if not self._factor_id and self._auth_token_partial:
                self._factor_id = self._start_2fa()

            if self._factor_id:
                logger.info("2FA required. Call verify_2fa() with the code.")
                return False

        logger.error(f"Login failed: {meta.get('message', 'unknown error')} (code={code})")
        return False

    def _start_2fa(self) -> str:
        """Get available 2FA factors and start verification."""
        # Get factors
        headers = {"Authorization": self._auth_token_partial}
        resp = self._auth_get(
            f"{ARLO_URLS['auth']}/getFactors?data={int(time.time() * 1000)}",
            extra_headers=headers,
        )

        if not resp or not resp.get("data"):
            logger.error("Failed to get 2FA factors")
            return ""

        factors = resp["data"].get("items", [])
        if not factors:
            logger.error("No 2FA factors available")
            return ""

        # Pick the first factor (usually email or SMS)
        factor = factors[0]
        factor_id = factor.get("factorId", "")
        factor_type = factor.get("factorType", "")
        logger.info(f"Using 2FA factor: {factor_type} ({factor_id})")

        # Start auth for this factor
        resp = self._auth_post(
            f"{ARLO_URLS['auth']}/startAuth",
            {"factorId": factor_id, "factorType": factor_type},
            extra_headers=headers,
        )

        if resp and resp.get("data"):
            return resp["data"].get("factorAuthId", "")

        return factor_id

    def verify_2fa(self, code: str) -> bool:
        """Complete 2FA verification with the code sent to your device."""
        if not self._factor_id:
            logger.error("No pending 2FA. Call login() first.")
            return False

        headers = {"Authorization": self._auth_token_partial}

        resp = self._auth_post(
            f"{ARLO_URLS['auth']}/finishAuth",
            {"factorAuthCode": code, "factorAuthId": self._factor_id},
            extra_headers=headers,
        )

        if not resp:
            return False

        data = resp.get("data", {})
        meta = resp.get("meta", {})

        if meta.get("code") == 200 and data.get("token"):
            return self._complete_auth(data)

        # Try alternative endpoint
        resp = self._auth_post(
            f"{ARLO_URLS['auth']}/validateAccessToken",
            {"factorAuthCode": code},
            extra_headers=headers,
        )

        if resp and resp.get("data", {}).get("token"):
            return self._complete_auth(resp["data"])

        logger.error(f"2FA failed: {meta.get('message', 'invalid code')}")
        return False

    def login_with_token(self, token: str) -> bool:
        """Login using a previously saved auth token."""
        self.token = token
        self.session.headers["Authorization"] = token

        resp = self._get(f"{ARLO_URLS['base']}/users/profile")
        if resp and resp.get("data"):
            data = resp["data"]
            self.user_id = data.get("userId", "")
            self.authenticated = True
            self.web_id = f"{self.user_id}_web"
            logger.info(f"Token auth successful: {self.user_id}")
            return True

        logger.error("Token invalid or expired")
        self.session.headers.pop("Authorization", None)
        return False

    def _complete_auth(self, data: dict) -> bool:
        """Complete authentication with token data."""
        self.token = data.get("token", "")
        self.user_id = data.get("userId", "")

        if not self.token:
            logger.error("No token in auth response")
            return False

        self.authenticated = True
        self.web_id = f"{self.user_id}_web"
        self.session.headers["Authorization"] = self.token

        logger.info(f"Authenticated as {self.user_id}")
        return True

    # === Device Discovery ===

    def get_devices(self) -> bool:
        """Fetch all devices from Arlo cloud and identify cameras."""
        if not self.authenticated:
            logger.error("Not authenticated. Call login() first.")
            return False

        # Try v2 endpoint first, fall back to v1
        resp = self._get(f"{ARLO_URLS['base']}/v2/users/devices")
        if not resp or not resp.get("data"):
            resp = self._get(f"{ARLO_URLS['base']}/users/devices")

        if not resp or not resp.get("data"):
            logger.error("Failed to get device list")
            return False

        devices = resp["data"]
        if not isinstance(devices, list):
            logger.debug(f"Unexpected devices format: {type(devices)}: {str(devices)[:200]}")
            devices = [devices] if isinstance(devices, dict) else []
        logger.info(f"Found {len(devices)} devices")
        logger.debug(f"Device types: {[type(d).__name__ for d in devices]}")

        for dev in devices:
            if not isinstance(dev, dict):
                logger.debug(f"Skipping non-dict device entry: {dev}")
                continue
            device_type = dev.get("deviceType", "").lower()
            device_id = dev.get("deviceId", "")
            model = dev.get("modelId", "").lower()

            if device_type in ("camera", "arlocqs", "arloq", "arloqs", "doorbell"):
                cam = ArloCloudCamera(
                    device_id=device_id,
                    parent_id=dev.get("parentId", ""),
                    unique_id=dev.get("uniqueId", ""),
                    serial=dev.get("serialNumber", ""),
                    model=dev.get("modelId", ""),
                    name=dev.get("deviceName", ""),
                    firmware=dev.get("firmwareVersion", ""),
                    state=dev.get("state", "provisioned"),
                    user_id=dev.get("userId", ""),
                    xcloud_id=dev.get("xCloudId", ""),
                    properties=dev.get("properties", {}),
                )

                # Check PTZ capability
                if model in PTZ_MODELS:
                    cam.has_ptz = True
                if dev.get("properties", {}).get("ptz"):
                    cam.has_ptz = True
                capabilities = dev.get("capabilities", [])
                if capabilities and any("ptz" in str(c).lower() for c in capabilities):
                    cam.has_ptz = True

                self.cameras[device_id] = cam
                logger.info(f"Camera: {cam}")

            elif device_type in ("basestation", "siren", "arlobridge"):
                self.base_stations[device_id] = dev
                logger.info(f"Base station: {dev.get('deviceName')} ({device_id})")

        return True

    # === Event Stream (SSE) ===

    def start_event_stream(self):
        """Start the SSE event stream for async command responses."""
        if self._event_running:
            return

        self._event_running = True
        self._event_thread = threading.Thread(
            target=self._event_loop, daemon=True, name="arlo-sse"
        )
        self._event_thread.start()
        time.sleep(2)

    def _event_loop(self):
        """Listen to Arlo's SSE event stream."""
        url = f"{ARLO_URLS['base']}/client/subscribe"
        headers = dict(self.session.headers)
        headers["Accept"] = "text/event-stream"

        while self._event_running:
            try:
                resp = self.session.get(
                    url, headers=headers, stream=True, timeout=30
                )

                if resp.status_code != 200:
                    logger.warning(f"SSE stream returned {resp.status_code}")
                    time.sleep(5)
                    continue

                for line in resp.iter_lines(decode_unicode=True):
                    if not self._event_running:
                        break
                    if not line:
                        continue

                    if line.startswith("data:"):
                        raw = line[5:].strip()
                    elif line.startswith("{"):
                        raw = line
                    else:
                        continue

                    try:
                        event = json.loads(raw)
                    except (json.JSONDecodeError, ValueError):
                        continue

                    self._handle_event(event)

            except requests.exceptions.Timeout:
                continue
            except Exception as e:
                if self._event_running:
                    logger.debug(f"SSE error: {e}, reconnecting...")
                    time.sleep(3)

    def _handle_event(self, event: dict):
        """Process an SSE event."""
        trans_id = event.get("transId", "")

        if trans_id and trans_id in self._pending:
            self._responses[trans_id] = event
            self._pending[trans_id].set()

        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.debug(f"Event callback error: {e}")

        resource = event.get("resource", "")
        if "ptz" in resource.lower():
            logger.debug(f"PTZ event: {json.dumps(event)}")

    def stop_event_stream(self):
        self._event_running = False
        if self._event_thread:
            self._event_thread.join(timeout=5)

    def on_event(self, callback: Callable):
        """Register a callback for SSE events."""
        self._event_callbacks.append(callback)

    # === Command Sending ===

    def _next_trans_id(self) -> str:
        with self._trans_lock:
            self._trans_id += 1
            return f"web!{uuid.uuid4().hex[:8]}!{self._trans_id}"

    def notify(
        self,
        device_id: str,
        action: str,
        resource: str,
        properties: dict,
        publish_response: bool = False,
        timeout: float = 10.0,
    ) -> Optional[dict]:
        """
        Send a command to a device through Arlo's cloud.

        This is the core command mechanism — same format as
        the base station local API but routed through cloud.
        """
        camera = self.cameras.get(device_id)
        parent_id = camera.parent_id if camera else device_id

        trans_id = self._next_trans_id()

        payload = {
            "action": action,
            "resource": resource,
            "publishResponse": publish_response,
            "transId": trans_id,
            "from": self.web_id,
            "to": parent_id,
            "properties": properties,
        }

        if camera and camera.parent_id and camera.parent_id != camera.device_id:
            payload["to"] = camera.parent_id

        if publish_response:
            event = threading.Event()
            self._pending[trans_id] = event

        url = f"{ARLO_URLS['base']}/users/devices/notify/{parent_id}"
        resp = self._post(url, payload)

        if not resp:
            return None

        if publish_response:
            event = self._pending.get(trans_id)
            if event and event.wait(timeout=timeout):
                result = self._responses.pop(trans_id, None)
                self._pending.pop(trans_id, None)
                return result
            self._pending.pop(trans_id, None)

        return resp

    # === PTZ Control ===

    def move(
        self,
        camera_id: str,
        pan: float = 0.0,
        tilt: float = 0.0,
        zoom: float = 0.0,
        speed: float = 0.5,
        duration: float = 0.5,
    ) -> bool:
        """Move camera by relative amounts."""
        cam = self.cameras.get(camera_id)
        if cam and not cam.has_ptz:
            logger.warning(f"Camera {camera_id} may not support PTZ (model: {cam.model})")

        result = self.notify(
            device_id=camera_id,
            action="set",
            resource="cameras/ptz",
            properties={
                "action": "move",
                "pan": max(-1.0, min(1.0, pan)),
                "tilt": max(-1.0, min(1.0, tilt)),
                "zoom": max(-1.0, min(1.0, zoom)),
                "speed": max(0.0, min(1.0, speed)),
                "duration": duration,
            },
        )

        if result is not None:
            logger.info(f"Move: pan={pan:.2f} tilt={tilt:.2f} zoom={zoom:.2f}")
        return result is not None

    def move_to(
        self,
        camera_id: str,
        pan: float,
        tilt: float,
        zoom: float = 0.0,
        speed: float = 0.5,
    ) -> bool:
        """Move camera to absolute position."""
        result = self.notify(
            device_id=camera_id,
            action="set",
            resource="cameras/ptz/position",
            properties={
                "action": "set",
                "pan": max(-1.0, min(1.0, pan)),
                "tilt": max(-1.0, min(1.0, tilt)),
                "zoom": max(0.0, min(1.0, zoom)),
                "speed": max(0.0, min(1.0, speed)),
            },
        )
        return result is not None

    def stop_move(self, camera_id: str) -> bool:
        result = self.notify(
            camera_id, "set", "cameras/ptz",
            {"action": "stop"},
        )
        return result is not None

    def go_home(self, camera_id: str) -> bool:
        result = self.notify(
            camera_id, "set", "cameras/ptz",
            {"action": "home"},
        )
        return result is not None

    def set_preset(self, camera_id: str, preset_id: int, name: str = "") -> bool:
        props: dict[str, Any] = {"action": "setPreset", "presetId": preset_id}
        if name:
            props["presetName"] = name
        result = self.notify(camera_id, "set", "cameras/ptz/preset", props)
        return result is not None

    def go_to_preset(self, camera_id: str, preset_id: int) -> bool:
        result = self.notify(
            camera_id, "set", "cameras/ptz/preset",
            {"action": "gotoPreset", "presetId": preset_id},
        )
        return result is not None

    def start_patrol(self, camera_id: str, preset_ids: Optional[list[int]] = None) -> bool:
        props: dict[str, Any] = {"action": "startPatrol"}
        if preset_ids:
            props["presetIds"] = preset_ids
        result = self.notify(camera_id, "set", "cameras/ptz/patrol", props)
        return result is not None

    def stop_patrol(self, camera_id: str) -> bool:
        result = self.notify(
            camera_id, "set", "cameras/ptz/patrol",
            {"action": "stopPatrol"},
        )
        return result is not None

    # === Camera Settings ===

    def toggle_night_vision(self, camera_id: str, enabled: bool) -> bool:
        result = self.notify(
            camera_id, "set", "cameras",
            {"nightVisionMode": 1 if enabled else 0},
        )
        return result is not None

    def set_brightness(self, camera_id: str, level: int) -> bool:
        result = self.notify(
            camera_id, "set", "cameras",
            {"brightness": max(-2, min(2, level))},
        )
        return result is not None

    def toggle_privacy(self, camera_id: str, enabled: bool) -> bool:
        result = self.notify(
            camera_id, "set", "cameras",
            {"privacyActive": enabled},
        )
        return result is not None

    def trigger_snapshot(self, camera_id: str) -> Optional[str]:
        result = self.notify(
            camera_id, "set", "cameras",
            {"activityState": "fullFrameSnapshot"},
            publish_response=True, timeout=15.0,
        )
        if result and isinstance(result, dict):
            return result.get("properties", {}).get("presignedFullFrameSnapshotUrl")
        return None

    def start_stream(self, camera_id: str) -> Optional[str]:
        """Start live stream. Returns stream URL if available."""
        camera = self.cameras.get(camera_id)
        parent_id = camera.parent_id if camera else camera_id

        resp = self._post(
            f"{ARLO_URLS['base']}/users/devices/startStream",
            {
                "to": parent_id,
                "from": self.web_id,
                "resource": f"cameras/{camera_id}",
                "action": "set",
                "publishResponse": True,
                "transId": self._next_trans_id(),
                "properties": {
                    "activityState": "startUserStream",
                    "cameraId": camera_id,
                },
            },
        )

        if resp and resp.get("data"):
            url = resp["data"].get("url", "")
            if url:
                logger.info(f"Stream URL: {url}")
                return url

        return None

    def stop_stream(self, camera_id: str) -> bool:
        result = self.notify(
            camera_id, "set", "cameras",
            {"activityState": "idle"},
        )
        return result is not None

    # === Raw Command ===

    def send_raw(
        self,
        camera_id: str,
        action: str,
        resource: str,
        properties: dict,
    ) -> Optional[dict]:
        """Send a raw command for experimentation."""
        return self.notify(
            camera_id, action, resource, properties,
            publish_response=True, timeout=10.0,
        )

    # === HTTP Helpers ===

    def _auth_get(self, url: str, extra_headers: Optional[dict] = None) -> Optional[dict]:
        """GET request using the auth session (cloudscraper for Cloudflare)."""
        try:
            headers = dict(self._auth_headers)
            if extra_headers:
                headers.update(extra_headers)
            resp = self._auth_session.get(url, headers=headers, timeout=15)
            logger.debug(f"AUTH GET {url} -> {resp.status_code}")
            if resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
            return None
        except Exception as e:
            logger.error(f"AUTH GET {url} failed: {e}")
            return None

    def _auth_post(self, url: str, body: dict, extra_headers: Optional[dict] = None) -> Optional[dict]:
        """POST request using the auth session (cloudscraper for Cloudflare)."""
        try:
            headers = dict(self._auth_headers)
            if extra_headers:
                headers.update(extra_headers)
            resp = self._auth_session.post(url, json=body, headers=headers, timeout=15)
            logger.debug(f"AUTH POST {url} -> {resp.status_code}")
            if resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
            logger.debug(f"AUTH response body: {resp.text[:500]}")
            return {"status": resp.status_code, "text": resp.text[:500]}
        except Exception as e:
            logger.error(f"AUTH POST {url} failed: {e}")
            return None

    def _get(self, url: str, extra_headers: Optional[dict] = None) -> Optional[dict]:
        """GET request using the API session."""
        try:
            headers = dict(self.session.headers)
            if extra_headers:
                headers.update(extra_headers)
            resp = self.session.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            logger.debug(f"GET {url} -> {resp.status_code}")
            if resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
            return None
        except Exception as e:
            logger.error(f"GET {url} failed: {e}")
            return None

    def _post(self, url: str, body: dict, extra_headers: Optional[dict] = None) -> Optional[dict]:
        """POST request using the API session."""
        try:
            headers = dict(self.session.headers)
            if extra_headers:
                headers.update(extra_headers)
            resp = self.session.post(url, json=body, headers=headers, timeout=15)
            if resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
            return {"status": resp.status_code}
        except Exception as e:
            logger.error(f"POST {url} failed: {e}")
            return None

    def close(self):
        """Logout and cleanup."""
        self.stop_event_stream()
        try:
            self._get(f"{ARLO_URLS['base']}/logout")
        except Exception:
            pass
        self.session.close()
        self._auth_session.close()
