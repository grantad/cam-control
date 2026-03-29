"""
SIP-over-TLS client for Arlo camera PTZ control.

Arlo cameras require PTZ commands to be sent within an active SIP session
(via SIP INFO messages), not just through the REST notify endpoint.

Flow:
  1. startStream → get sipCallInfo + RTSP URL
  2. Connect TLS to SIP server (domain:port from sipCallInfo)
  3. INVITE with WebRTC SDP → 407 Digest challenge → re-INVITE with auth → 200 OK → ACK
  4. Send PTZ commands as SIP INFO with JSON body
  5. BYE to tear down

Uses aiortc for real WebRTC SDP generation — Arlo's FreeSWITCH rejects
static/fake SDPs with 488 Not Acceptable Here.
"""

import asyncio
import hashlib
import json
import logging
import re
import socket
import ssl
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer
    HAS_AIORTC = True
except ImportError:
    HAS_AIORTC = False


def _generate_sdp(ice_data: list) -> str:
    """Generate a real WebRTC SDP offer using aiortc with Arlo's ICE servers."""
    if not HAS_AIORTC:
        raise RuntimeError("aiortc is required for SIP PTZ. Install: pip install aiortc")

    ice_servers = []
    for s in (ice_data or []):
        if s.get("type") == "stun":
            ice_servers.append(RTCIceServer(urls=[f"stun:{s['domain']}:{s['port']}"]))
        elif s.get("type") == "turn":
            proto = s.get("transport", "udp")
            ice_servers.append(RTCIceServer(
                urls=[f"turn:{s['domain']}:{s['port']}?transport={proto}"],
                username=s.get("username", ""),
                credential=s.get("credential", ""),
            ))

    async def _make_offer():
        pc = RTCPeerConnection(
            configuration=RTCConfiguration(iceServers=ice_servers)
        )
        pc.addTransceiver("video", direction="recvonly")
        pc.addTransceiver("audio", direction="recvonly")
        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        # Wait for ICE gathering to complete
        while pc.iceGatheringState != "complete":
            await asyncio.sleep(0.1)
        sdp = pc.localDescription.sdp
        await pc.close()
        return sdp

    # Run in a fresh event loop (safe from any thread)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, _make_offer())
        return future.result(timeout=30)


class SIPClient:
    """
    SIP client for Arlo PTZ control over TLS.

    Establishes a SIP dialog via INVITE (with Digest auth) and sends
    PTZ commands as SIP INFO messages with JSON payloads.
    """

    def __init__(self):
        self.sock: Optional[ssl.SSLSocket] = None
        self.cseq = 0
        self._tag = ""
        self._call_id = ""
        self._to_tag = ""
        self.domain = ""
        self.port = 0
        self.caller_id = ""
        self.callee_uri = ""
        self.password = ""
        self._alive = False

    @property
    def is_alive(self) -> bool:
        return self._alive and self.sock is not None

    def establish(self, sip_info: dict, ice_data: list = None) -> bool:
        """
        Establish a SIP dialog using sipCallInfo from startStream.

        Args:
            sip_info: dict with keys: domain, port, id, calleeUri, password
            ice_data: list of ICE server dicts from stream_data["iceServers"]["data"]

        Returns:
            True if SIP dialog is established and ready for INFO commands.
        """
        self.domain = sip_info["domain"]
        self.port = sip_info["port"]
        self.caller_id = sip_info["id"]
        self.callee_uri = sip_info["calleeUri"]
        self.password = sip_info["password"]
        self._tag = uuid.uuid4().hex[:8]
        self._call_id = uuid.uuid4().hex
        self._to_tag = ""
        self.cseq = 0
        self._alive = False

        # Generate real WebRTC SDP via aiortc
        logger.info("Generating WebRTC SDP offer via aiortc...")
        try:
            sdp = _generate_sdp(ice_data)
            logger.info(f"SDP ready: {len(sdp)} bytes")
        except Exception as e:
            logger.error(f"SDP generation failed: {e}")
            return False

        # TLS connect to SIP server
        logger.info(f"Connecting to SIP server {self.domain}:{self.port}...")
        try:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
            raw = socket.create_connection((self.domain, self.port), timeout=10)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.domain)
        except Exception as e:
            logger.error(f"TLS connect failed: {e}")
            return False

        # INVITE (expect 407 Proxy-Authenticate)
        self.cseq += 1
        invite_msg = self._build_invite(sdp)
        logger.debug(f"Sending INVITE ({len(invite_msg)} bytes) CSeq={self.cseq}")
        self.sock.sendall(invite_msg.encode())
        resp = self._read(timeout=15)

        logger.debug(f"INVITE response ({len(resp)} bytes):\n{resp[:800]}")

        if "407" not in resp:
            codes = re.findall(r"SIP/2\.0 (\d+) ([^\r\n]+)", resp)
            logger.error(f"Expected 407, got codes={codes}, full resp:\n{resp[:500]}")
            return False

        logger.info("Got 407 — computing Digest auth...")

        # Parse digest challenge
        realm_m = re.search(r'realm="([^"]+)"', resp)
        nonce_m = re.search(r'nonce="([^"]+)"', resp)
        if not realm_m or not nonce_m:
            logger.error("No digest challenge in 407 response")
            return False

        realm = realm_m.group(1)
        nonce = nonce_m.group(1)

        # ACK the 407 (to-tag already extracted by _read)
        self.cseq += 1
        self.sock.sendall(self._build_ack().encode())
        time.sleep(0.5)

        # Compute Digest auth
        ha1 = hashlib.md5(f"{self.caller_id}:{realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"INVITE:{self.callee_uri}".encode()).hexdigest()
        digest = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        auth_header = (
            f'Proxy-Authorization: Digest username="{self.caller_id}", '
            f'realm="{realm}", nonce="{nonce}", '
            f'uri="{self.callee_uri}", response="{digest}", algorithm=MD5'
        )

        # Re-INVITE with auth — give server up to 30s to respond
        self.cseq += 1
        invite_msg = self._build_invite(sdp, auth_header)
        logger.debug(f"Sending authenticated INVITE ({len(invite_msg)} bytes) CSeq={self.cseq}")
        self.sock.sendall(invite_msg.encode())
        resp = self._read(timeout=30)

        all_codes = re.findall(r"SIP/2\.0 (\d+) ([^\r\n]+)", resp)
        logger.debug(f"Auth INVITE response codes={all_codes}, ({len(resp)} bytes):\n{resp[:800]}")

        if "200 OK" not in resp:
            logger.error(f"INVITE failed: codes={all_codes}, response:\n{resp[:500]}")
            return False

        # ACK the 200 OK (to-tag already extracted by _read)
        self.cseq += 1
        self.sock.sendall(self._build_ack().encode())
        self._alive = True

        logger.info("SIP dialog established — ready for PTZ commands")
        return True

    def send_ptz(self, command: dict) -> str:
        """
        Send a PTZ command via SIP INFO.

        Args:
            command: JSON-serializable PTZ command, e.g.:
                {"action": "continuousMove", "velocity": {"x": 0.5, "y": 0.0}}
                {"action": "stopMove"}

        Returns:
            SIP response status string (e.g. "200 OK") or error description.
        """
        if not self.is_alive:
            return "NO SESSION"

        body = json.dumps(command)
        self.cseq += 1

        to_line = f"<{self.callee_uri}>"
        if self._to_tag:
            to_line += f";tag={self._to_tag}"

        msg = (
            f"INFO {self.callee_uri} SIP/2.0\r\n"
            f"Via: SIP/2.0/TLS {self.domain}:{self.port};branch={self._branch()}\r\n"
            f"From: <sip:{self.caller_id}@{self.domain}>;tag={self._tag}\r\n"
            f"To: {to_line}\r\n"
            f"Call-ID: {self._call_id}\r\n"
            f"CSeq: {self.cseq} INFO\r\n"
            f"Content-Type: application/json\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        )

        try:
            self.sock.sendall(msg.encode())
            resp = self._read(timeout=5)
            m = re.search(r"SIP/2\.0 (\d+) (.+?)(?:\r\n|\n)", resp)
            status = f"{m.group(1)} {m.group(2)}" if m else "???"

            # Session-killing errors
            if any(code in status for code in ("486", "481", "408")):
                logger.warning(f"SIP session ended: {status}")
                self._alive = False

            return status
        except Exception as e:
            self._alive = False
            return f"ERROR: {e}"

    def close(self):
        """Send BYE and close the TLS socket."""
        if self.sock:
            if self._alive:
                try:
                    self._send_bye()
                except Exception:
                    pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self._alive = False

    # --- SIP message builders ---

    def _branch(self) -> str:
        return f"z9hG4bK{uuid.uuid4().hex[:12]}"

    def _build_invite(self, sdp: str, auth_header: Optional[str] = None) -> str:
        lines = [
            f"INVITE {self.callee_uri} SIP/2.0",
            f"Via: SIP/2.0/TLS {self.domain}:{self.port};branch={self._branch()}",
            f"From: <sip:{self.caller_id}@{self.domain}>;tag={self._tag}",
            f"To: <{self.callee_uri}>",
            f"Call-ID: {self._call_id}",
            f"CSeq: {self.cseq} INVITE",
            f"Contact: <sip:{self.caller_id}@{self.domain};transport=tls>",
            "Max-Forwards: 70",
            "User-Agent: CamControl/1.0",
        ]
        if auth_header:
            lines.append(auth_header)
        lines.extend([
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp)}",
            "",
            sdp,
        ])
        return "\r\n".join(lines)

    def _build_ack(self) -> str:
        to_line = f"<{self.callee_uri}>"
        if self._to_tag:
            to_line += f";tag={self._to_tag}"
        return (
            f"ACK {self.callee_uri} SIP/2.0\r\n"
            f"Via: SIP/2.0/TLS {self.domain}:{self.port};branch={self._branch()}\r\n"
            f"From: <sip:{self.caller_id}@{self.domain}>;tag={self._tag}\r\n"
            f"To: {to_line}\r\n"
            f"Call-ID: {self._call_id}\r\n"
            f"CSeq: {self.cseq} ACK\r\n"
            f"Content-Length: 0\r\n\r\n"
        )

    def _send_bye(self):
        self.cseq += 1
        to_line = f"<{self.callee_uri}>"
        if self._to_tag:
            to_line += f";tag={self._to_tag}"
        msg = (
            f"BYE {self.callee_uri} SIP/2.0\r\n"
            f"Via: SIP/2.0/TLS {self.domain}:{self.port};branch={self._branch()}\r\n"
            f"From: <sip:{self.caller_id}@{self.domain}>;tag={self._tag}\r\n"
            f"To: {to_line}\r\n"
            f"Call-ID: {self._call_id}\r\n"
            f"CSeq: {self.cseq} BYE\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        self.sock.sendall(msg.encode())

    def _read(self, timeout: float = 10) -> str:
        """Read SIP response, waiting for a final status code (>= 200).
        Also extracts to-tag from any response (needed for ACKing 407s).
        """
        self.sock.settimeout(timeout)
        buf = b""
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                remaining = max(1, deadline - time.monotonic())
                self.sock.settimeout(min(remaining, 5))
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                text = buf.decode(errors="replace")

                # Always extract to-tag from responses (407 includes one)
                tt = re.search(r"To:.*?;tag=(\S+)", text)
                if tt:
                    self._to_tag = tt.group(1)

                # Check for final response (>= 200)
                codes = [int(m.group(1)) for m in re.finditer(r"SIP/2\.0 (\d+)", text)]
                if any(c >= 200 for c in codes):
                    # Drain any remaining data
                    time.sleep(0.3)
                    self.sock.settimeout(1)
                    try:
                        while True:
                            more = self.sock.recv(65536)
                            if not more:
                                break
                            buf += more
                    except socket.timeout:
                        pass
                    text = buf.decode(errors="replace")
                    # Re-extract to-tag from full response
                    tt = re.search(r"To:.*?;tag=(\S+)", text)
                    if tt:
                        self._to_tag = tt.group(1)
                    return text
            except socket.timeout:
                continue

        return buf.decode(errors="replace")
