"""
Arlo device discovery on the local network.
Finds base stations and cameras via ARP scanning, MAC fingerprinting,
and service probing.
"""

import socket
import threading
import time
import logging
import ssl
import json
from typing import Optional
from dataclasses import dataclass, field

from scapy.all import (
    ARP, Ether, IP, TCP, UDP, Raw,
    srp, conf, sniff as scapy_sniff
)

logger = logging.getLogger(__name__)

# Arlo MAC prefixes (base stations and cameras share these)
ARLO_MAC_PREFIXES = {
    "48:62:64": "Arlo",
    "20:0d:b0": "Arlo",
    "9c:53:22": "Arlo",
    "e0:63:da": "Arlo",
    "cc:40:d0": "Arlo",
    "50:c7:bf": "Arlo/Netgear",
    "a0:04:60": "Arlo/Netgear",
    "6c:b0:ce": "Arlo/Netgear",
    "44:94:fc": "Arlo/Netgear",
}

# Ports the Arlo base station listens on locally
ARLO_BASE_PORTS = [443, 4443, 80, 8443]

# Ports used for camera-to-base communication
ARLO_CAMERA_PORTS = [8000, 8082, 9000]


@dataclass
class ArloDevice:
    ip: str
    mac: str = ""
    device_type: str = ""       # "base_station" or "camera"
    model: str = ""
    serial: str = ""
    firmware: str = ""
    friendly_name: str = ""
    open_ports: list = field(default_factory=list)
    has_ptz: bool = False
    capabilities: list = field(default_factory=list)

    def __str__(self):
        label = self.friendly_name or self.model or self.device_type
        ptz = " [PTZ]" if self.has_ptz else ""
        return f"{label}{ptz} @ {self.ip} ({self.mac})"


def get_subnet(interface: Optional[str] = None) -> Optional[str]:
    """Get the subnet CIDR for the given interface."""
    try:
        import netifaces
        iface = interface or str(conf.iface)
        addrs = netifaces.ifaddresses(iface)
        ipv4 = addrs.get(netifaces.AF_INET, [{}])[0]
        ip_addr = ipv4.get("addr")
        netmask = ipv4.get("netmask")
        if ip_addr and netmask:
            mask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
            ip_parts = ip_addr.split('.')
            ip_parts[3] = '0'
            return f"{'.'.join(ip_parts)}/{mask_bits}"
    except ImportError:
        pass

    try:
        iface = interface or str(conf.iface)
        if iface:
            ip_addr = conf.route.route("0.0.0.0")[1]
            if ip_addr:
                parts = ip_addr.split('.')
                parts[3] = '0'
                return f"{'.'.join(parts)}/24"
    except Exception:
        pass

    return None


def arp_scan(subnet: str, timeout: float = 3.0) -> list[dict]:
    """ARP scan the subnet. Returns list of {ip, mac} dicts."""
    logger.info(f"ARP scanning {subnet}...")
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=timeout,
        verbose=False
    )
    hosts = []
    for _, recv in ans:
        hosts.append({"ip": recv.psrc, "mac": recv.hwsrc.lower()})
    logger.info(f"Found {len(hosts)} hosts")
    return hosts


def is_arlo_mac(mac: str) -> bool:
    """Check if MAC belongs to an Arlo device."""
    prefix = mac.lower()[:8]
    return prefix in ARLO_MAC_PREFIXES


def tcp_port_scan(ip: str, ports: list[int], timeout: float = 1.5) -> list[int]:
    """Scan TCP ports on a host."""
    open_ports = []

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=check_port, args=(port,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=timeout + 0.5)

    return sorted(open_ports)


def probe_arlo_https(ip: str, port: int = 443, timeout: float = 5.0) -> Optional[dict]:
    """
    Probe an Arlo base station's HTTPS service.
    The base station uses self-signed certs and exposes a local API.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=ip)
        ssock.connect((ip, port))

        # Try the device info endpoint
        request = (
            f"GET /hmsweb/users/device/info HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"User-Agent: CamControl/1.0\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        ssock.send(request.encode())

        response = b""
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        ssock.close()
        resp_str = response.decode("utf-8", errors="replace")

        info = {"port": port, "is_arlo": False}

        # Check for Arlo-specific response headers/content
        resp_lower = resp_str.lower()
        if any(marker in resp_lower for marker in [
            "arlo", "netgear", "hmsweb", "basestation",
            "x-arlo", "vmb", "smarthub"
        ]):
            info["is_arlo"] = True

        # Try to parse JSON body
        if "\r\n\r\n" in resp_str:
            body = resp_str.split("\r\n\r\n", 1)[1]
            # Strip chunked encoding if present
            if body and body[0].isdigit():
                lines = body.split("\r\n")
                body = "".join(lines[1::2])  # every other line is chunk data
            try:
                data = json.loads(body)
                info["data"] = data
                info["is_arlo"] = True
            except (json.JSONDecodeError, ValueError):
                pass

        # Check TLS certificate for Arlo identifiers
        cert = ssock.getpeercert() if hasattr(ssock, 'getpeercert') else None
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            org = subject.get("organizationName", "").lower()
            cn = subject.get("commonName", "").lower()
            if "arlo" in org or "netgear" in org or "arlo" in cn:
                info["is_arlo"] = True

        return info if info["is_arlo"] else None

    except ssl.SSLError:
        # SSL handshake happened — likely an HTTPS service, could be Arlo
        return {"port": port, "is_arlo": True, "ssl_only": True}
    except ConnectionRefusedError:
        return None
    except Exception as e:
        logger.debug(f"HTTPS probe {ip}:{port} failed: {e}")
        return None


def classify_device(host: dict, open_ports: list[int]) -> Optional[ArloDevice]:
    """
    Classify an Arlo device as base station or camera based on
    open ports and network behavior.
    """
    device = ArloDevice(
        ip=host["ip"],
        mac=host["mac"],
    )

    # Base stations have HTTPS ports open
    base_ports = set(open_ports) & set(ARLO_BASE_PORTS)
    cam_ports = set(open_ports) & set(ARLO_CAMERA_PORTS)

    if base_ports:
        device.device_type = "base_station"
        device.open_ports = list(base_ports)
    elif cam_ports:
        device.device_type = "camera"
        device.open_ports = list(cam_ports)
    else:
        # Default: if it has 443 open it's likely a base station
        if 443 in open_ports:
            device.device_type = "base_station"
        else:
            device.device_type = "camera"
        device.open_ports = open_ports

    return device


def discover_arlo_devices(
    subnet: Optional[str] = None,
    interface: Optional[str] = None,
    base_station_ip: Optional[str] = None,
) -> tuple[list[ArloDevice], list[ArloDevice]]:
    """
    Discover Arlo devices on the network.

    Returns:
        (base_stations, cameras) tuple of ArloDevice lists
    """
    base_stations = []
    cameras = []

    # If base station IP is known, probe it directly
    if base_station_ip:
        logger.info(f"Probing known base station at {base_station_ip}...")
        ports = tcp_port_scan(base_station_ip, ARLO_BASE_PORTS + ARLO_CAMERA_PORTS)
        device = ArloDevice(
            ip=base_station_ip,
            device_type="base_station",
            open_ports=ports,
        )
        # Try HTTPS probe for device info
        for port in [443, 4443, 8443]:
            if port in ports:
                info = probe_arlo_https(base_station_ip, port)
                if info and info.get("data"):
                    data = info["data"]
                    device.model = data.get("modelId", "")
                    device.serial = data.get("deviceId", "")
                    device.firmware = data.get("firmwareVersion", "")
                    device.friendly_name = data.get("deviceName", "")
                break
        base_stations.append(device)
        return base_stations, cameras

    # Auto-discovery via ARP scan
    if subnet is None:
        subnet = get_subnet(interface)
    if subnet is None:
        logger.error("Could not determine subnet. Use --subnet or set in config.")
        return base_stations, cameras

    hosts = arp_scan(subnet)

    # Filter to Arlo MACs
    arlo_hosts = [h for h in hosts if is_arlo_mac(h["mac"])]

    if not arlo_hosts:
        # Fallback: scan all hosts for Arlo HTTPS service
        logger.info("No Arlo MACs found. Probing all hosts for Arlo services...")
        for host in hosts:
            ports = tcp_port_scan(host["ip"], [443, 4443])
            for port in ports:
                info = probe_arlo_https(host["ip"], port)
                if info and info.get("is_arlo"):
                    arlo_hosts.append(host)
                    break

    logger.info(f"Found {len(arlo_hosts)} Arlo device(s)")

    for host in arlo_hosts:
        # Port scan to classify
        all_ports = ARLO_BASE_PORTS + ARLO_CAMERA_PORTS
        open_ports = tcp_port_scan(host["ip"], all_ports)

        device = classify_device(host, open_ports)
        if not device:
            continue

        # Probe HTTPS on base stations for detailed info
        if device.device_type == "base_station":
            for port in [443, 4443, 8443]:
                if port in open_ports:
                    info = probe_arlo_https(host["ip"], port)
                    if info and info.get("data"):
                        data = info["data"]
                        device.model = data.get("modelId", "")
                        device.serial = data.get("deviceId", "")
                        device.firmware = data.get("firmwareVersion", "")
                        device.friendly_name = data.get("deviceName", "")
                    break
            base_stations.append(device)
        else:
            cameras.append(device)

    return base_stations, cameras


def print_devices(base_stations: list[ArloDevice], cameras: list[ArloDevice]):
    """Pretty-print discovered Arlo devices."""
    total = len(base_stations) + len(cameras)
    if total == 0:
        print("\n  No Arlo devices found on the network.")
        print("  Make sure you're on the same network as your Arlo base station.")
        print("  Try specifying --subnet or --base-ip if auto-detection fails.\n")
        return

    print(f"\n  Found {total} Arlo device(s):\n")

    if base_stations:
        print(f"  Base Stations ({len(base_stations)}):")
        print(f"  {'IP':<16} {'MAC':<18} {'Model':<14} {'Serial':<20} {'Ports'}")
        print(f"  {'-'*16} {'-'*18} {'-'*14} {'-'*20} {'-'*15}")
        for bs in base_stations:
            ports_str = ",".join(str(p) for p in bs.open_ports)
            print(
                f"  {bs.ip:<16} {bs.mac:<18} "
                f"{bs.model or '-':<14} {bs.serial or '-':<20} {ports_str}"
            )
        print()

    if cameras:
        print(f"  Cameras ({len(cameras)}):")
        print(f"  {'IP':<16} {'MAC':<18} {'Model':<14} {'PTZ':<6} {'Ports'}")
        print(f"  {'-'*16} {'-'*18} {'-'*14} {'-'*6} {'-'*15}")
        for cam in cameras:
            ports_str = ",".join(str(p) for p in cam.open_ports)
            ptz_str = "Yes" if cam.has_ptz else "-"
            print(
                f"  {cam.ip:<16} {cam.mac:<18} "
                f"{cam.model or '-':<14} {ptz_str:<6} {ports_str}"
            )
        print()
