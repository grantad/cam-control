"""
Local Arlo base station API client.
Communicates directly with the base station over HTTPS on the LAN,
bypassing Arlo's cloud services entirely.

The base station exposes a REST API that the Arlo app uses.
We reverse-engineer and replay these commands for direct control.
"""

import json
import time
import logging
import ssl
import threading
import uuid
from typing import Optional, Any
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

logger = logging.getLogger(__name__)


class ArloSSLAdapter(HTTPAdapter):
    """
    Custom SSL adapter that accepts the base station's self-signed cert
    and uses TLS settings compatible with the Arlo firmware.
    """
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Some Arlo firmware versions need specific ciphers
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


@dataclass
class ArloCamera:
    """Represents a camera paired with the base station."""
    device_id: str
    serial: str = ""
    model: str = ""
    name: str = ""
    firmware: str = ""
    has_ptz: bool = False
    ptz_range: dict = field(default_factory=dict)
    state: str = "unknown"
    battery: int = -1
    signal_strength: int = -1

    def __str__(self):
        ptz = " [PTZ]" if self.has_ptz else ""
        return f"{self.name or self.model}{ptz} ({self.device_id})"


@dataclass
class PTZPosition:
    """Current PTZ position of a camera."""
    pan: float = 0.0     # horizontal: -1.0 (left) to 1.0 (right)
    tilt: float = 0.0    # vertical: -1.0 (down) to 1.0 (up)
    zoom: float = 0.0    # zoom: 0.0 (wide) to 1.0 (tele)

    def __str__(self):
        return f"pan={self.pan:.2f} tilt={self.tilt:.2f} zoom={self.zoom:.2f}"


class ArloLocalAPI:
    """
    Direct local API client for Arlo base stations.

    Sends commands to the base station over HTTPS on the LAN.
    The base station relays them to cameras over its proprietary
    wireless protocol.

    Command flow: This client → Base Station (LAN) → Camera (wireless)
    No cloud involved.
    """

    def __init__(
        self,
        base_station_ip: str,
        port: int = 443,
        auth_token: Optional[str] = None,
    ):
        self.base_url = f"https://{base_station_ip}:{port}"
        self.base_station_ip = base_station_ip
        self.port = port
        self.auth_token = auth_token

        # Session with custom SSL handling
        self.session = requests.Session()
        self.session.mount("https://", ArloSSLAdapter())
        self.session.verify = False

        # Suppress insecure request warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Transaction ID counter
        self._trans_id = 0
        self._trans_lock = threading.Lock()

        # SSE event stream for async responses
        self._event_thread: Optional[threading.Thread] = None
        self._event_running = False
        self._pending_responses: dict[str, Any] = {}
        self._response_events: dict[str, threading.Event] = {}

        # Discovered cameras
        self.cameras: dict[str, ArloCamera] = {}
        self.base_station_id: str = ""

    def _next_trans_id(self) -> str:
        """Generate unique transaction ID for request tracking."""
        with self._trans_lock:
            self._trans_id += 1
            return f"CC!{self._trans_id}!{int(time.time() * 1000)}"

    def _headers(self) -> dict:
        """Build request headers mimicking the Arlo app."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
            "Origin": f"https://{self.base_station_ip}",
            "Referer": f"https://{self.base_station_ip}/",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
            headers["X-Arlo-Token"] = self.auth_token
        return headers

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        timeout: float = 10.0,
    ) -> Optional[dict]:
        """Send a request to the base station."""
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(
                method=method,
                url=url,
                json=body,
                headers=self._headers(),
                timeout=timeout,
            )
            logger.debug(f"{method} {path} -> {resp.status_code}")

            if resp.status_code == 401:
                logger.error("Auth token rejected. Re-run intercept to capture a fresh token.")
                return None

            if resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
            return {"status": resp.status_code, "text": resp.text}

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to base station at {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Request failed: {method} {path}: {e}")
            return None

    def _send_action(
        self,
        camera_id: str,
        action: str,
        resource: str,
        properties: dict,
        publish_response: bool = False,
        timeout: float = 10.0,
    ) -> Optional[dict]:
        """
        Send an action command through the base station.

        This is the core command format used by Arlo's protocol:
        The base station acts as a message broker between the app
        and cameras using a publish/subscribe model.
        """
        trans_id = self._next_trans_id()

        payload = {
            "action": action,
            "resource": resource,
            "publishResponse": publish_response,
            "transId": trans_id,
            "from": f"{self.base_station_id}_web",
            "to": camera_id,
            "properties": properties,
        }

        # If we need the response, set up a waiter
        if publish_response:
            event = threading.Event()
            self._response_events[trans_id] = event

        result = self._request("POST", "/hmsweb/users/device/notify", payload, timeout)

        if publish_response and result:
            # Wait for async response via SSE
            event = self._response_events.get(trans_id)
            if event and event.wait(timeout=timeout):
                return self._pending_responses.pop(trans_id, None)

        return result

    # === Device Discovery ===

    def connect(self) -> bool:
        """
        Connect to the base station and enumerate cameras.
        Returns True if successful.
        """
        logger.info(f"Connecting to Arlo base station at {self.base_url}...")

        # Get base station info
        info = self._request("GET", "/hmsweb/users/device/info")
        if not info:
            # Try alternative endpoint paths
            for path in ["/api/device/info", "/device/info", "/"]:
                info = self._request("GET", path)
                if info:
                    break

        if info:
            self.base_station_id = info.get("deviceId", info.get("serialNumber", ""))
            logger.info(
                f"Connected to base station: "
                f"model={info.get('modelId', '?')} "
                f"serial={self.base_station_id} "
                f"fw={info.get('firmwareVersion', '?')}"
            )
        else:
            logger.warning("Could not get base station info (may need auth token)")

        # Enumerate cameras
        self._discover_cameras()

        return bool(self.cameras) or bool(self.base_station_id)

    def _discover_cameras(self):
        """Get list of cameras paired with this base station."""
        # Try various endpoints for camera listing
        for path in [
            "/hmsweb/users/devices",
            "/hmsweb/users/device/cameras",
            "/api/devices",
        ]:
            result = self._request("GET", path)
            if not result:
                continue

            devices = result if isinstance(result, list) else result.get("data", [])
            if not isinstance(devices, list):
                continue

            for dev in devices:
                if not isinstance(dev, dict):
                    continue
                device_type = dev.get("deviceType", "").lower()
                if device_type in ("camera", "arlocam", ""):
                    cam = ArloCamera(
                        device_id=dev.get("deviceId", dev.get("serialNumber", "")),
                        serial=dev.get("serialNumber", ""),
                        model=dev.get("modelId", ""),
                        name=dev.get("deviceName", ""),
                        firmware=dev.get("firmwareVersion", ""),
                        state=dev.get("state", "unknown"),
                    )

                    # Check PTZ capability
                    capabilities = dev.get("capabilities", [])
                    properties = dev.get("properties", {})

                    if isinstance(capabilities, list):
                        cam.has_ptz = any(
                            c in ["ptz", "pan", "tilt", "zoom", "motor"]
                            for c in [str(x).lower() for x in capabilities]
                        )

                    if isinstance(properties, dict):
                        if "ptz" in properties or "motorizedPan" in properties:
                            cam.has_ptz = True

                    # PTZ-capable models (known)
                    ptz_models = [
                        "vmc4040p", "vmc4041p", "vmc4050p", "vmc5040",
                        "vmc4060p", "abc1000", "vmc2040",
                        "vml4030", "vml2030",  # Arlo Essential Indoor
                    ]
                    if any(m in cam.model.lower() for m in ptz_models):
                        cam.has_ptz = True

                    self.cameras[cam.device_id] = cam
                    logger.info(f"Found camera: {cam}")

            if self.cameras:
                break

        if not self.cameras:
            logger.warning("No cameras found. They may need to be discovered via intercept mode.")

    # === PTZ Control ===

    def get_ptz_position(self, camera_id: str) -> Optional[PTZPosition]:
        """Get the current PTZ position of a camera."""
        result = self._send_action(
            camera_id=camera_id,
            action="get",
            resource="cameras/ptz",
            properties={},
            publish_response=True,
            timeout=5.0,
        )

        if result and isinstance(result, dict):
            props = result.get("properties", result)
            return PTZPosition(
                pan=float(props.get("pan", 0)),
                tilt=float(props.get("tilt", 0)),
                zoom=float(props.get("zoom", 0)),
            )
        return None

    def move(
        self,
        camera_id: str,
        pan: float = 0.0,
        tilt: float = 0.0,
        zoom: float = 0.0,
        speed: float = 0.5,
        duration: float = 0.5,
    ) -> bool:
        """
        Move the camera by relative amounts.

        Args:
            camera_id: Target camera device ID
            pan:  Horizontal movement (-1.0 left to 1.0 right)
            tilt: Vertical movement (-1.0 down to 1.0 up)
            zoom: Zoom change (-1.0 out to 1.0 in)
            speed: Movement speed (0.0 to 1.0)
            duration: Movement duration in seconds
        """
        cam = self.cameras.get(camera_id)
        if cam and not cam.has_ptz:
            logger.error(f"Camera {camera_id} does not support PTZ")
            return False

        properties = {
            "action": "move",
            "pan": max(-1.0, min(1.0, pan)),
            "tilt": max(-1.0, min(1.0, tilt)),
            "zoom": max(-1.0, min(1.0, zoom)),
            "speed": max(0.0, min(1.0, speed)),
            "duration": duration,
        }

        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz",
            properties=properties,
        )

        success = result is not None
        if success:
            logger.info(
                f"Move: pan={pan:.2f} tilt={tilt:.2f} zoom={zoom:.2f} "
                f"speed={speed:.1f} dur={duration:.1f}s"
            )
        return success

    def move_to(
        self,
        camera_id: str,
        pan: float,
        tilt: float,
        zoom: float = 0.0,
        speed: float = 0.5,
    ) -> bool:
        """
        Move camera to an absolute position.

        Args:
            camera_id: Target camera device ID
            pan:  Absolute horizontal position (-1.0 to 1.0)
            tilt: Absolute vertical position (-1.0 to 1.0)
            zoom: Absolute zoom level (0.0 to 1.0)
            speed: Movement speed
        """
        properties = {
            "action": "set",
            "pan": max(-1.0, min(1.0, pan)),
            "tilt": max(-1.0, min(1.0, tilt)),
            "zoom": max(0.0, min(1.0, zoom)),
            "speed": max(0.0, min(1.0, speed)),
        }

        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz/position",
            properties=properties,
        )

        success = result is not None
        if success:
            logger.info(f"Move to: pan={pan:.2f} tilt={tilt:.2f} zoom={zoom:.2f}")
        return success

    def stop_move(self, camera_id: str) -> bool:
        """Immediately stop any ongoing PTZ movement."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz",
            properties={"action": "stop"},
        )
        return result is not None

    def go_home(self, camera_id: str) -> bool:
        """Return camera to its home/default position."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz",
            properties={"action": "home"},
        )
        if result is not None:
            logger.info("Camera returning to home position")
        return result is not None

    def set_preset(self, camera_id: str, preset_id: int, name: str = "") -> bool:
        """Save the current position as a named preset."""
        properties = {
            "action": "setPreset",
            "presetId": preset_id,
        }
        if name:
            properties["presetName"] = name

        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz/preset",
            properties=properties,
        )
        if result is not None:
            logger.info(f"Saved preset {preset_id}: {name or '(unnamed)'}")
        return result is not None

    def go_to_preset(self, camera_id: str, preset_id: int) -> bool:
        """Move camera to a saved preset position."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz/preset",
            properties={
                "action": "gotoPreset",
                "presetId": preset_id,
            },
        )
        if result is not None:
            logger.info(f"Moving to preset {preset_id}")
        return result is not None

    def start_patrol(self, camera_id: str, preset_ids: Optional[list[int]] = None) -> bool:
        """Start automated patrol between preset positions."""
        properties: dict[str, Any] = {"action": "startPatrol"}
        if preset_ids:
            properties["presetIds"] = preset_ids

        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz/patrol",
            properties=properties,
        )
        if result is not None:
            logger.info(f"Patrol started (presets: {preset_ids or 'all'})")
        return result is not None

    def stop_patrol(self, camera_id: str) -> bool:
        """Stop automated patrol."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras/ptz/patrol",
            properties={"action": "stopPatrol"},
        )
        return result is not None

    # === Camera Settings ===

    def get_camera_state(self, camera_id: str) -> Optional[dict]:
        """Get full camera state including settings."""
        result = self._send_action(
            camera_id=camera_id,
            action="get",
            resource="cameras",
            properties={},
            publish_response=True,
        )
        return result

    def set_brightness(self, camera_id: str, level: int) -> bool:
        """Set camera brightness (-2 to 2)."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras",
            properties={"brightness": max(-2, min(2, level))},
        )
        return result is not None

    def toggle_night_vision(self, camera_id: str, enabled: bool) -> bool:
        """Enable/disable night vision."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras",
            properties={"nightVisionMode": 1 if enabled else 0},
        )
        return result is not None

    def toggle_privacy_mode(self, camera_id: str, enabled: bool) -> bool:
        """Enable/disable privacy mode (turns camera off/on)."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras",
            properties={"privacyActive": enabled},
        )
        return result is not None

    def trigger_snapshot(self, camera_id: str) -> Optional[str]:
        """Trigger the camera to take a snapshot. Returns URL if available."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras",
            properties={"activityState": "fullFrameSnapshot"},
            publish_response=True,
        )
        if result and isinstance(result, dict):
            return result.get("properties", {}).get("presignedFullFrameSnapshotUrl")
        return None

    def start_stream(self, camera_id: str) -> Optional[str]:
        """
        Start a live stream from the camera.
        Returns the local stream URL if available.
        """
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras",
            properties={"activityState": "startUserStream"},
            publish_response=True,
            timeout=15.0,
        )
        if result and isinstance(result, dict):
            url = result.get("properties", {}).get("streamUrl")
            if url:
                logger.info(f"Stream URL: {url}")
            return url
        return None

    def stop_stream(self, camera_id: str) -> bool:
        """Stop a live stream."""
        result = self._send_action(
            camera_id=camera_id,
            action="set",
            resource="cameras",
            properties={"activityState": "idle"},
        )
        return result is not None

    # === Raw Command Interface ===

    def send_raw(
        self,
        camera_id: str,
        action: str,
        resource: str,
        properties: dict,
    ) -> Optional[dict]:
        """
        Send a raw command to a camera.
        Use this to replay captured commands or experiment with
        undocumented actions.
        """
        return self._send_action(
            camera_id=camera_id,
            action=action,
            resource=resource,
            properties=properties,
            publish_response=True,
        )

    def replay_command(self, captured_command: dict) -> Optional[dict]:
        """
        Replay a previously captured command (from interceptor).
        Accepts a command dict from CapturedCommand.to_dict().
        """
        body = captured_command.get("body", {})
        if not body:
            logger.error("Cannot replay command with no body")
            return None

        # Extract action components
        camera_id = body.get("to", "")
        action = body.get("action", "set")
        resource = body.get("resource", "")
        properties = body.get("properties", {})

        if not camera_id or not resource:
            logger.error("Command missing 'to' or 'resource' field")
            return None

        logger.info(f"Replaying: {action} {resource} -> {camera_id}")
        return self.send_raw(camera_id, action, resource, properties)

    # === Event Stream ===

    def start_event_stream(self):
        """
        Start listening to the base station's SSE event stream.
        This receives async responses to commands.
        """
        if self._event_running:
            return

        self._event_running = True
        self._event_thread = threading.Thread(
            target=self._event_loop, daemon=True, name="arlo-events"
        )
        self._event_thread.start()

    def _event_loop(self):
        """Listen to SSE event stream from the base station."""
        url = f"{self.base_url}/hmsweb/client/subscribe"
        headers = self._headers()
        headers["Accept"] = "text/event-stream"

        while self._event_running:
            try:
                resp = self.session.get(
                    url, headers=headers, stream=True, timeout=30
                )

                for line in resp.iter_lines(decode_unicode=True):
                    if not self._event_running:
                        break
                    if not line or not line.startswith("data:"):
                        continue

                    try:
                        data = json.loads(line[5:].strip())
                        trans_id = data.get("transId", "")

                        # Match to pending request
                        if trans_id in self._response_events:
                            self._pending_responses[trans_id] = data
                            self._response_events[trans_id].set()

                        # Log interesting events
                        resource = data.get("resource", "")
                        if "ptz" in resource.lower():
                            logger.debug(f"PTZ event: {json.dumps(data)}")

                    except (json.JSONDecodeError, ValueError):
                        pass

            except Exception as e:
                if self._event_running:
                    logger.debug(f"Event stream error: {e}, reconnecting...")
                    time.sleep(2)

    def stop_event_stream(self):
        self._event_running = False
        if self._event_thread:
            self._event_thread.join(timeout=5)

    def close(self):
        """Clean up resources."""
        self.stop_event_stream()
        self.session.close()
