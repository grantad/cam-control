#!/usr/bin/env python3
"""
CamControl — Multi-Brand Camera Hijacker & PTZ Controller

Control Arlo and Wyze cameras without the vendor apps.
Supports cloud API control for both brands.

Usage:
    python main.py discover                        # Find Arlo devices on LAN
    python main.py cloud-login                     # Auth with Arlo cloud
    python main.py wyze-login                      # Auth with Wyze cloud
    python main.py wyze-bridge start               # Start docker-wyze-bridge for PTZ
    python main.py control                         # Interactive PTZ (auto-detects brand)
    python main.py control --brand arlo            # Force Arlo
    python main.py control --brand wyze            # Force Wyze
    python main.py control --mode local --base-ip X  # Arlo local base station mode
    python main.py move --dir left                 # One-shot movement (Arlo)
    python main.py intercept --base-ip <IP>        # MITM to capture base station commands
    python main.py replay <capture_file>           # Replay captured commands

Discovery/intercept require root/sudo. Cloud mode does NOT require sudo.
"""

import os
import sys
import signal
import subprocess
import time
import argparse
import logging
import json
import getpass
from typing import Optional

import yaml

from discovery import discover_arlo_devices, print_devices, get_subnet
from arlo_cloud import ArloCloudAPI
from wyze_cloud import WyzeCloudAPI

logger = logging.getLogger("camcontrol")


def load_config(path: str = "config.yaml") -> dict:
    default_config = {
        "network": {"interface": None, "subnet": None},
        "arlo": {
            "base_station_ip": None,
            "auth_token": None,
            "camera_serial": None,
            "email": None,
            "mode": "cloud",  # "cloud" or "local"
        },
        "wyze": {
            "email": None,
            "password": None,
            "key_id": None,
            "api_key": None,
            "camera_mac": None,
            "bridge_url": "http://localhost:5000",
        },
        "intercept": {
            "capture_dir": "./captures",
        },
        "control": {
            "move_speed": 0.5,
            "move_duration": 0.5,
            "step_interval": 0.1,
        },
    }

    if os.path.exists(path):
        with open(path) as f:
            user_config = yaml.safe_load(f) or {}

        def merge(base, override):
            for k, v in override.items():
                if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                    merge(base[k], v)
                else:
                    base[k] = v

        merge(default_config, user_config)

    return default_config


def save_config(config: dict, path: str = "config.yaml"):
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


# === Cloud API helpers ===

def cloud_login(config: dict, config_path: str) -> ArloCloudAPI:
    """Authenticate with Arlo cloud and return API client."""
    api = ArloCloudAPI()

    # Try saved token first
    token = config["arlo"].get("auth_token")
    if token:
        print("  Trying saved auth token...")
        if api.login_with_token(token):
            print("  Authenticated with saved token.")
            return api
        print("  Saved token expired.")

    # Interactive login
    email = config["arlo"].get("email") or input("  Arlo email: ").strip()
    password = getpass.getpass("  Arlo password: ")

    if api.login(email, password):
        print("  Login successful!")
    else:
        # Check for 2FA
        if hasattr(api, '_factor_id') and api._factor_id:
            if api._factor_type == "PUSH":
                print("  Push notification sent to your phone. Approve it...")
                if not api.verify_2fa():
                    print("  Push approval failed or timed out.")
                    sys.exit(1)
                print("  Push approved!")
            else:
                print(f"  2FA required ({api._factor_type}). Check your email/phone.")
                code = input("  2FA code: ").strip()
                if not api.verify_2fa(code):
                    print("  2FA verification failed.")
                    sys.exit(1)
                print("  2FA verified!")
        else:
            print("  Login failed. Check credentials.")
            sys.exit(1)

    # Save token and email for next time
    config["arlo"]["auth_token"] = api.token
    config["arlo"]["email"] = email
    save_config(config, config_path)
    print(f"  Token saved to {config_path}")

    return api


def select_camera(api: ArloCloudAPI, preferred_id: Optional[str] = None, force_pick: bool = False) -> str:
    """Select a camera from the API's device list."""
    if not api.cameras:
        api.get_devices()

    if not api.cameras:
        print("  No cameras found on your Arlo account.")
        sys.exit(1)

    # Auto-select PTZ camera pool
    ptz_cameras = {k: v for k, v in api.cameras.items() if v.has_ptz}
    pool = ptz_cameras if ptz_cameras else api.cameras

    # Use preferred if it exists and we're not forcing a pick
    if preferred_id and preferred_id in pool and not force_pick:
        cam = pool[preferred_id]
        print(f"  Using camera: {cam}")
        return preferred_id

    if len(pool) == 1 and not force_pick:
        cid = list(pool.keys())[0]
        print(f"  Auto-selected: {pool[cid]}")
        return cid

    # Show picker
    print(f"\n  Cameras ({len(pool)}):")
    items = list(pool.items())
    for i, (cid, cam) in enumerate(items):
        marker = " <-- current" if cid == preferred_id else ""
        print(f"    [{i}] {cam}{marker}")

    try:
        choice = input("\n  Select camera [0]: ").strip()
        idx = int(choice) if choice else 0
        return items[idx][0]
    except (ValueError, IndexError):
        return items[0][0]


# === CLI Commands ===

def cmd_discover(args, config):
    """Discover Arlo devices on the network."""
    print("\n  CamControl — Arlo Device Discovery\n")

    base_stations, cameras = discover_arlo_devices(
        subnet=args.subnet or config["network"]["subnet"],
        interface=args.interface or config["network"]["interface"],
        base_station_ip=getattr(args, 'base_ip', None) or config["arlo"]["base_station_ip"],
    )

    print_devices(base_stations, cameras)

    if args.save and base_stations:
        config["arlo"]["base_station_ip"] = base_stations[0].ip
        save_config(config, args.config)
        print(f"  Saved base station IP to {args.config}\n")


def cmd_cloud_login(args, config):
    """Authenticate with Arlo cloud and list devices."""
    print("\n  CamControl — Arlo Cloud Login\n")

    api = cloud_login(config, args.config)

    print("\n  Fetching devices...")
    api.get_devices()

    if api.cameras:
        print(f"\n  Cameras ({len(api.cameras)}):")
        for cid, cam in api.cameras.items():
            ptz = " [PTZ]" if cam.has_ptz else ""
            print(f"    {cam.name}{ptz} — {cam.model} ({cid})")

            # Save first PTZ camera as default
            if cam.has_ptz and not config["arlo"]["camera_serial"]:
                config["arlo"]["camera_serial"] = cid

    if api.base_stations:
        print(f"\n  Base Stations ({len(api.base_stations)}):")
        for bsid, bs in api.base_stations.items():
            print(f"    {bs.get('deviceName', '?')} ({bsid})")

    save_config(config, args.config)
    print(f"\n  Ready! Run:  python main.py control")
    print()
    api.close()


def cmd_control(args, config):
    """Interactive PTZ control — supports Arlo and Wyze."""
    brand = getattr(args, 'brand', None)

    if not brand:
        # Auto-detect: check which brands have credentials
        has_arlo = bool(config["arlo"].get("auth_token") or config["arlo"].get("email"))
        has_wyze = bool(config["wyze"].get("email") or config["wyze"].get("bridge_url"))
        if has_arlo and has_wyze:
            choice = input("  Brand [arlo/wyze]: ").strip().lower()
            brand = choice if choice in ("arlo", "wyze") else "arlo"
        elif has_wyze:
            brand = "wyze"
        else:
            brand = "arlo"

    if brand == "wyze":
        print("\n" + "=" * 60)
        print(f"  CamControl — Interactive Camera Control (Wyze cloud)")
        print("=" * 60)
        _control_wyze(args, config)
    else:
        mode = getattr(args, 'mode', None) or config["arlo"].get("mode", "cloud")
        print("\n" + "=" * 60)
        print(f"  CamControl — Interactive Camera Control (Arlo {mode})")
        print("=" * 60)
        if mode == "cloud":
            _control_cloud(args, config)
        else:
            _control_local(args, config)


def _control_cloud(args, config):
    """Cloud-mode control for direct-WiFi cameras."""
    api = cloud_login(config, args.config)
    api.get_devices()

    # If --camera is passed, use it; otherwise always show picker
    explicit_camera = getattr(args, 'camera', None)
    saved_camera = config["arlo"]["camera_serial"]
    force_pick = not explicit_camera  # show picker unless explicitly specified

    camera_id = select_camera(
        api,
        explicit_camera or saved_camera,
        force_pick=force_pick,
    )

    # Save selection
    config["arlo"]["camera_serial"] = camera_id
    save_config(config, args.config)

    # Start event stream
    print("  Starting event stream...")
    api.start_event_stream()

    ccfg = config["control"]

    print(f"\n  Camera: {api.cameras.get(camera_id, camera_id)}")
    print(f"  Speed:  {ccfg['move_speed']}")
    print()

    _run_interactive_cloud(api, camera_id, ccfg, config, args.config)


def _control_wyze(args, config):
    """Wyze cloud control via wyze-sdk + docker-wyze-bridge."""
    bridge_url = config["wyze"].get("bridge_url", "http://localhost:5000")
    api = WyzeCloudAPI(bridge_url=bridge_url)

    # Try auth: wyze-sdk first, then bridge-only
    email = config["wyze"].get("email")
    password = config["wyze"].get("password")

    if email and password:
        key_id = config["wyze"].get("key_id") or ""
        api_key = config["wyze"].get("api_key") or ""
        if not api.login(email, password, key_id, api_key):
            print("  Wyze login failed. Trying bridge-only mode...")
            if not api.login_with_bridge():
                print("  Error: Cannot connect to Wyze. Run 'wyze-login' or start the bridge.")
                sys.exit(1)
    else:
        print("  No Wyze credentials saved. Trying bridge-only mode...")
        if not api.login_with_bridge():
            print("  Error: Cannot connect to wyze-bridge.")
            print("  Run 'wyze-login' first, or start the bridge with 'wyze-bridge start'.")
            sys.exit(1)

    api.get_devices()

    if not api.cameras:
        print("  No Wyze cameras found.")
        sys.exit(1)

    # Select camera
    preferred = config["wyze"].get("camera_mac")
    camera_id = select_camera_generic(api, preferred)
    config["wyze"]["camera_mac"] = camera_id
    save_config(config, args.config)

    # Check bridge for PTZ
    if not api.check_bridge():
        print("  Warning: docker-wyze-bridge not reachable at " + bridge_url)
        print("  PTZ commands will fail. Start it with: python main.py wyze-bridge start")

    print(f"\n  Camera: {api.cameras.get(camera_id, camera_id)}")
    print()

    _run_interactive(api, camera_id, config, args.config)


def select_camera_generic(api, preferred_id: Optional[str] = None) -> str:
    """Brand-agnostic camera picker."""
    pool = {k: v for k, v in api.cameras.items() if v.has_ptz}
    if not pool:
        pool = api.cameras

    if preferred_id and preferred_id in pool:
        cam = pool[preferred_id]
        print(f"  Using camera: {cam}")
        return preferred_id

    if len(pool) == 1:
        cid = list(pool.keys())[0]
        print(f"  Auto-selected: {pool[cid]}")
        return cid

    print(f"\n  Cameras ({len(pool)}):")
    items = list(pool.items())
    for i, (cid, cam) in enumerate(items):
        marker = " <-- current" if cid == preferred_id else ""
        print(f"    [{i}] {cam}{marker}")

    try:
        choice = input("\n  Select camera [0]: ").strip()
        idx = int(choice) if choice else 0
        return items[idx][0]
    except (ValueError, IndexError):
        return items[0][0]


def cmd_wyze_login(args, config):
    """Authenticate with Wyze and list devices."""
    print("\n  CamControl — Wyze Login\n")

    api = WyzeCloudAPI(bridge_url=config["wyze"].get("bridge_url", "http://localhost:5000"))

    email = config["wyze"].get("email") or input("  Wyze email: ").strip()
    password = getpass.getpass("  Wyze password: ")
    key_id = config["wyze"].get("key_id") or input("  API Key ID (optional, press Enter to skip): ").strip()
    api_key = ""
    if key_id:
        api_key = config["wyze"].get("api_key") or input("  API Key: ").strip()

    if not api.login(email, password, key_id, api_key):
        print("  Login failed. Check credentials.")
        print("  Note: If you use Google sign-in, set a Wyze password first:")
        print("    1. Go to wyze.com → 'Forgot Password'")
        print("    2. Use the email associated with your Google account")
        sys.exit(1)

    print("  Login successful!")

    # Save credentials
    config["wyze"]["email"] = email
    config["wyze"]["password"] = password  # TODO: use keyring for production
    if key_id:
        config["wyze"]["key_id"] = key_id
        config["wyze"]["api_key"] = api_key
    save_config(config, args.config)

    print("\n  Fetching devices...")
    api.get_devices()

    if api.cameras:
        print(f"\n  Cameras ({len(api.cameras)}):")
        for cid, cam in api.cameras.items():
            ptz = " [PTZ]" if cam.has_ptz else ""
            print(f"    {cam.name}{ptz} — {cam.model} ({cid})")

    # Check bridge
    if api.check_bridge():
        print(f"\n  docker-wyze-bridge: RUNNING at {api._bridge_url}")
    else:
        print(f"\n  docker-wyze-bridge: NOT RUNNING")
        print(f"  Start it for PTZ: python main.py wyze-bridge start")

    print(f"\n  Ready! Run:  python main.py control --brand wyze")
    print()
    api.close()


def cmd_wyze_bridge(args, config):
    """Start/stop docker-wyze-bridge."""
    action = getattr(args, 'action', 'start')
    compose_file = os.path.join(os.path.dirname(__file__) or ".", "docker-compose.wyze.yml")

    if not os.path.exists(compose_file):
        print(f"  Error: {compose_file} not found")
        sys.exit(1)

    if action == "start":
        print("  Starting docker-wyze-bridge...")
        print("  This requires Docker Desktop or colima to be running.\n")

        # Set env vars from config
        env = os.environ.copy()
        wyze_cfg = config.get("wyze", {})
        if wyze_cfg.get("email"):
            env["WYZE_EMAIL"] = wyze_cfg["email"]
        if wyze_cfg.get("password"):
            env["WYZE_PASSWORD"] = wyze_cfg["password"]
        if wyze_cfg.get("key_id"):
            env["WYZE_KEY_ID"] = wyze_cfg["key_id"]
        if wyze_cfg.get("api_key"):
            env["WYZE_API_KEY"] = wyze_cfg["api_key"]

        result = subprocess.run(
            ["docker-compose", "-f", compose_file, "up", "-d"],
            env=env,
        )
        if result.returncode == 0:
            print("\n  Bridge started! Cameras should appear within 30-60 seconds.")
            print(f"  REST API: http://localhost:5000")
            print(f"  RTSP:     rtsp://localhost:8554/<camera-name>")
        else:
            print("\n  Failed to start bridge. Is Docker running?")
            print("  Try: open -a Docker  (or: colima start)")

    elif action == "stop":
        print("  Stopping docker-wyze-bridge...")
        subprocess.run(["docker-compose", "-f", compose_file, "down"])

    elif action == "status":
        result = subprocess.run(
            ["docker-compose", "-f", compose_file, "ps"],
            capture_output=True, text=True,
        )
        print(result.stdout or "  No containers running.")


def _control_local(args, config):
    """Local-mode control via base station."""
    from arlo_api import ArloLocalAPI
    from controller import CameraController, MovementConfig

    base_ip = getattr(args, 'base_ip', None) or config["arlo"]["base_station_ip"]
    if not base_ip:
        print("  Error: Base station IP required for local mode.")
        print("  Run 'discover' first or use --base-ip")
        sys.exit(1)

    auth_token = getattr(args, 'token', None) or config["arlo"]["auth_token"]

    api = ArloLocalAPI(base_station_ip=base_ip, auth_token=auth_token)
    if not api.connect():
        print("  Warning: Could not fully connect.")
        print("  Try 'intercept' to capture an auth token.\n")

    camera_id = getattr(args, 'camera', None) or config["arlo"]["camera_serial"]
    if not camera_id and api.cameras:
        ptz = {k: v for k, v in api.cameras.items() if v.has_ptz}
        pool = ptz or api.cameras
        camera_id = list(pool.keys())[0]

    if not camera_id:
        camera_id = input("  Enter camera device ID: ").strip()
        if not camera_id:
            sys.exit(1)

    ccfg = config["control"]
    ctrl = CameraController(
        api, camera_id,
        MovementConfig(
            speed=ccfg["move_speed"],
            duration=ccfg["move_duration"],
            step_interval=ccfg["step_interval"],
        ),
    )

    api.start_event_stream()

    print(f"\n  Camera: {camera_id}")
    print(f"  Speed:  {ccfg['move_speed']}")
    print()
    _run_interactive_local(ctrl, api)


def _run_interactive_cloud(api: ArloCloudAPI, camera_id: str, ccfg: dict,
                           config: Optional[dict] = None, config_path: str = "config.yaml"):
    """Interactive control loop using cloud API with relativeMove PTZ."""
    step = 0.05  # relativeMove step size (matching Arlo app's 0.05 increments)
    stream_active = False
    ffmpeg_proc = None  # Background ffmpeg process consuming the stream

    def _ensure_stream():
        """Start stream and consume with ffplay."""
        nonlocal stream_active, camera_id, ffmpeg_proc
        # Stream already running and ffplay alive? Nothing to do.
        if stream_active and ffmpeg_proc and ffmpeg_proc.poll() is None:
            return True
        # Kill old ffplay if it died
        if ffmpeg_proc and ffmpeg_proc.poll() is not None:
            ffmpeg_proc = None
            stream_active = False

        if stream_active:
            return True  # Stream active but no ffplay (that's OK)

        print("  Starting stream (required for PTZ)...")
        url = api.start_stream(camera_id)

        if url:
            print(f"  Opening live view...")
            try:
                ffmpeg_proc = subprocess.Popen(
                    ["ffplay", "-rtsp_transport", "tcp", "-i", url,
                     "-window_title", "CamControl — Live View",
                     "-loglevel", "quiet", "-nostats",
                     "-fast", "-framedrop"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                print(f"  Live view window opened.")
            except FileNotFoundError:
                print("  Warning: ffplay not found — no live view.")
                print("  Install: brew install ffmpeg")
        else:
            print("  Stream start returned no URL (may still work).")

        stream_active = True
        time.sleep(5)  # Give camera time to fully wake up
        return True

    def _stop_stream():
        """Stop ffplay."""
        nonlocal ffmpeg_proc, stream_active
        if ffmpeg_proc:
            ffmpeg_proc.terminate()
            try:
                ffmpeg_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ffmpeg_proc.kill()
            ffmpeg_proc = None
        stream_active = False

    print("  === Controls ===")
    print("  Movement:    w/a/s/d or up/down/left/right")
    print("  Zoom:        +/- or z/x")
    print("  Home:        h")
    print("  Stop:        0")
    print("  Speed:       1-9 (0.1 - 0.9)")
    print("  Presets:     p1-p9 (goto), sp1-sp9 (save)")
    print("  Patterns:    sweep, patrol")
    print("  Camera:      snap, stream, night, nightoff, privacy, privacyoff")
    print("  Switch:      switch (pick a different camera), list (show all)")
    print("  Look at:     goto <pan> <tilt> [zoom]")
    print("  Raw:         raw <action> <resource> <json_properties>")
    print("  Quit:        q")
    print("  " + "-" * 50)
    print()
    print("  Note: First PTZ command will auto-start a stream.")
    print()

    while True:
        try:
            cmd = input("  cam> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue

        cmd_lower = cmd.lower()

        # Quit
        if cmd_lower in ("q", "quit", "exit"):
            break

        # Movement (auto-starts stream on first use)
        elif cmd_lower in ("w", "up"):
            _ensure_stream()
            api.move(camera_id, tilt=step)
        elif cmd_lower in ("s", "down"):
            _ensure_stream()
            api.move(camera_id, tilt=-step)
        elif cmd_lower in ("a", "left"):
            _ensure_stream()
            api.move(camera_id, pan=-step)
        elif cmd_lower in ("d", "right"):
            _ensure_stream()
            api.move(camera_id, pan=step)
        elif cmd_lower in ("+", "z", "zi", "zoomin"):
            _ensure_stream()
            api.move(camera_id, zoom=step)
        elif cmd_lower in ("-", "x", "zo", "zoomout"):
            _ensure_stream()
            api.move(camera_id, zoom=-step)

        # Diagonals
        elif cmd_lower in ("wa", "upleft"):
            _ensure_stream()
            api.move(camera_id, pan=-step, tilt=step)
        elif cmd_lower in ("wd", "upright"):
            _ensure_stream()
            api.move(camera_id, pan=step, tilt=step)
        elif cmd_lower in ("sa", "downleft"):
            _ensure_stream()
            api.move(camera_id, pan=-step, tilt=-step)
        elif cmd_lower in ("sd", "downright"):
            _ensure_stream()
            api.move(camera_id, pan=step, tilt=-step)

        # Stop / Home
        elif cmd_lower in ("0", "stop"):
            api.stop_move(camera_id)
            print("  Stopped.")
        elif cmd_lower in ("h", "home"):
            api.go_home(camera_id)
            print("  Returning home.")

        # Speed (adjusts step size for relativeMove)
        elif cmd_lower in [str(i) for i in range(1, 10)]:
            step = int(cmd_lower) * 0.01  # 0.01 to 0.09
            print(f"  Step size: {step}")

        # Presets (goto)
        elif cmd_lower.startswith("p") and len(cmd_lower) == 2 and cmd_lower[1].isdigit():
            pid = int(cmd_lower[1])
            api.go_to_preset(camera_id, pid)
            print(f"  Going to preset {pid}")

        # Presets (save)
        elif cmd_lower.startswith("sp") and len(cmd_lower) == 3 and cmd_lower[2].isdigit():
            pid = int(cmd_lower[2])
            name = input(f"  Preset {pid} name: ").strip()
            api.set_preset(camera_id, pid, name)
            print(f"  Saved preset {pid}")

        # Patterns
        elif cmd_lower == "sweep":
            _ensure_stream()
            print("  Sweeping...")
            for _ in range(6):
                api.move(camera_id, pan=0.05)
                time.sleep(0.8)
            api.stop_move(camera_id)
            time.sleep(0.5)
            for _ in range(6):
                api.move(camera_id, pan=-0.05)
                time.sleep(0.8)
            api.stop_move(camera_id)
            print("  Done.")

        elif cmd_lower == "patrol":
            api.start_patrol(camera_id)
            print("  Patrol started. Type 'stop' to end.")

        # Absolute move
        elif cmd_lower.startswith("goto "):
            parts = cmd_lower.split()
            try:
                pan = float(parts[1])
                tilt = float(parts[2])
                zoom = float(parts[3]) if len(parts) > 3 else 0.0
                api.move_to(camera_id, pan, tilt, zoom)
                print(f"  Moving to pan={pan} tilt={tilt} zoom={zoom}")
            except (IndexError, ValueError):
                print("  Usage: goto <pan> <tilt> [zoom]")

        # Camera functions (non-PTZ — always via REST)
        elif cmd_lower == "snap":
            url = api.trigger_snapshot(camera_id)
            print(f"  Snapshot: {url or 'triggered (no URL returned)'}")
        elif cmd_lower == "stream":
            url = api.start_stream(camera_id)
            print(f"  Stream: {url or 'started (no URL returned)'}")
        elif cmd_lower == "night":
            api.toggle_night_vision(camera_id, True)
            print("  Night vision ON")
        elif cmd_lower == "nightoff":
            api.toggle_night_vision(camera_id, False)
            print("  Night vision OFF")
        elif cmd_lower == "privacy":
            api.toggle_privacy(camera_id, True)
            print("  Privacy mode ON (camera off)")
        elif cmd_lower == "privacyoff":
            api.toggle_privacy(camera_id, False)
            print("  Privacy mode OFF (camera active)")

        # Probe PTZ
        elif cmd_lower == "test":
            _ensure_stream()
            print("  Testing PTZ (relativeMove)...")
            tests = [
                ("PAN RIGHT",  0.05, 0.0),
                ("PAN LEFT",   -0.05, 0.0),
                ("TILT UP",    0.0, 0.05),
                ("TILT DOWN",  0.0, -0.05),
            ]
            for label, x, y in tests:
                api.move(camera_id, pan=x, tilt=y)
                print(f"  {label}: sent")
                time.sleep(2)
            api.go_home(camera_id)
            print("  HOME: sent")
            print("  Done. Watch the live view for movement!")

        # Raw command (still via REST for flexibility)
        elif cmd_lower.startswith("raw "):
            parts = cmd.split(maxsplit=3)
            if len(parts) < 4:
                print("  Usage: raw <action> <resource> <json_properties>")
                continue
            try:
                props = json.loads(parts[3])
                result = api.send_raw(camera_id, parts[1], parts[2], props)
                print(f"  Result: {json.dumps(result, indent=2) if result else 'no response'}")
            except json.JSONDecodeError:
                print("  Error: Invalid JSON properties")

        # Switch camera
        elif cmd_lower in ("switch", "sw"):
            new_id = select_camera(api, camera_id, force_pick=True)
            if new_id != camera_id:
                _stop_stream()  # Stop stream for old camera
                camera_id = new_id
                if config:
                    config["arlo"]["camera_serial"] = camera_id
                    save_config(config, config_path)
            print(f"  Now controlling: {api.cameras.get(camera_id, camera_id)}")

        # List cameras
        elif cmd_lower in ("list", "ls", "cameras"):
            for cid, cam in api.cameras.items():
                marker = " <-- active" if cid == camera_id else ""
                print(f"  {cam}{marker}")

        elif cmd_lower in ("status", "info"):
            cam = api.cameras.get(camera_id)
            if cam:
                print(f"  Name:  {cam.name}")
                print(f"  Model: {cam.model}")
                print(f"  PTZ:   {cam.has_ptz}")
                print(f"  State: {cam.state}")
                print(f"  ID:    {cam.device_id}")
            print(f"  Step:  {step}")

        else:
            print(f"  Unknown: {cmd}")
            print("  w/a/s/d=move, +/-=zoom, h=home, switch=change camera, q=quit")

    print("\n  Disconnecting...")
    _stop_stream()
    api.close()
    print("  Done.\n")


def _run_interactive(api, camera_id: str, config: Optional[dict] = None,
                     config_path: str = "config.yaml"):
    """Brand-agnostic interactive control loop. Works with any CameraAPI."""
    is_arlo = isinstance(api, ArloCloudAPI)
    is_wyze = isinstance(api, WyzeCloudAPI)
    brand = "wyze" if is_wyze else "arlo"

    step = 0.05  # Default step size
    stream_active = False
    ffmpeg_proc = None

    def _ensure_stream():
        nonlocal stream_active, camera_id, ffmpeg_proc
        if stream_active and ffmpeg_proc and ffmpeg_proc.poll() is None:
            return True
        if ffmpeg_proc and ffmpeg_proc.poll() is not None:
            ffmpeg_proc = None
            stream_active = False
        if stream_active:
            return True

        print("  Starting stream...")
        url = api.start_stream(camera_id)
        if url:
            print(f"  Opening live view...")
            try:
                ffplay_args = ["ffplay", "-i", url,
                               "-window_title", "CamControl — Live View",
                               "-loglevel", "quiet", "-nostats",
                               "-fast", "-framedrop"]
                # Arlo uses rtsps (TLS), needs tcp transport
                if url.startswith("rtsps://"):
                    ffplay_args = ["ffplay", "-rtsp_transport", "tcp", "-i", url,
                                   "-window_title", "CamControl — Live View",
                                   "-loglevel", "quiet", "-nostats",
                                   "-fast", "-framedrop"]
                ffmpeg_proc = subprocess.Popen(
                    ffplay_args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                print(f"  Live view window opened.")
            except FileNotFoundError:
                print("  Warning: ffplay not found — no live view.")
        else:
            print("  No stream URL (may still work for PTZ).")

        stream_active = True
        if is_arlo:
            time.sleep(5)  # Arlo needs time to wake up
        return True

    def _stop_stream():
        nonlocal ffmpeg_proc, stream_active
        if ffmpeg_proc:
            ffmpeg_proc.terminate()
            try:
                ffmpeg_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ffmpeg_proc.kill()
            ffmpeg_proc = None
        stream_active = False

    print("  === Controls ===")
    print("  Movement:    w/a/s/d or up/down/left/right")
    print("  Zoom:        +/- or z/x")
    print("  Home:        h")
    print("  Stop:        0")
    print("  Speed:       1-9 (step size)")
    if is_arlo:
        print("  Presets:     p1-p9 (goto), sp1-sp9 (save)")
        print("  Patterns:    sweep, patrol")
    else:
        print("  Patterns:    sweep")
    print("  Camera:      snap, stream, night, nightoff, privacy, privacyoff")
    print("  Switch:      switch (pick a different camera), list (show all)")
    print("  Look at:     goto <pan> <tilt> [zoom]")
    if is_arlo:
        print("  Raw:         raw <action> <resource> <json>")
    print("  Quit:        q")
    print("  " + "-" * 50)
    print()

    while True:
        try:
            cmd = input("  cam> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue

        cmd_lower = cmd.lower()

        if cmd_lower in ("q", "quit", "exit"):
            break

        elif cmd_lower in ("w", "up"):
            _ensure_stream()
            api.move(camera_id, tilt=step)
        elif cmd_lower in ("s", "down"):
            _ensure_stream()
            api.move(camera_id, tilt=-step)
        elif cmd_lower in ("a", "left"):
            _ensure_stream()
            api.move(camera_id, pan=-step)
        elif cmd_lower in ("d", "right"):
            _ensure_stream()
            api.move(camera_id, pan=step)
        elif cmd_lower in ("+", "z", "zi", "zoomin"):
            _ensure_stream()
            api.move(camera_id, zoom=step)
        elif cmd_lower in ("-", "x", "zo", "zoomout"):
            _ensure_stream()
            api.move(camera_id, zoom=-step)

        elif cmd_lower in ("wa", "upleft"):
            _ensure_stream()
            api.move(camera_id, pan=-step, tilt=step)
        elif cmd_lower in ("wd", "upright"):
            _ensure_stream()
            api.move(camera_id, pan=step, tilt=step)
        elif cmd_lower in ("sa", "downleft"):
            _ensure_stream()
            api.move(camera_id, pan=-step, tilt=-step)
        elif cmd_lower in ("sd", "downright"):
            _ensure_stream()
            api.move(camera_id, pan=step, tilt=-step)

        elif cmd_lower in ("0", "stop"):
            api.stop_move(camera_id)
            print("  Stopped.")
        elif cmd_lower in ("h", "home"):
            api.go_home(camera_id)
            print("  Returning home.")

        elif cmd_lower in [str(i) for i in range(1, 10)]:
            step = int(cmd_lower) * 0.01
            print(f"  Step size: {step}")

        # Arlo-only: presets
        elif is_arlo and cmd_lower.startswith("p") and len(cmd_lower) == 2 and cmd_lower[1].isdigit():
            pid = int(cmd_lower[1])
            api.go_to_preset(camera_id, pid)
            print(f"  Going to preset {pid}")
        elif is_arlo and cmd_lower.startswith("sp") and len(cmd_lower) == 3 and cmd_lower[2].isdigit():
            pid = int(cmd_lower[2])
            name = input(f"  Preset {pid} name: ").strip()
            api.set_preset(camera_id, pid, name)
            print(f"  Saved preset {pid}")

        elif cmd_lower == "sweep":
            _ensure_stream()
            print("  Sweeping...")
            for _ in range(6):
                api.move(camera_id, pan=step)
                time.sleep(0.8)
            api.stop_move(camera_id)
            time.sleep(0.5)
            for _ in range(6):
                api.move(camera_id, pan=-step)
                time.sleep(0.8)
            api.stop_move(camera_id)
            print("  Done.")

        elif is_arlo and cmd_lower == "patrol":
            api.start_patrol(camera_id)
            print("  Patrol started. Type 'stop' to end.")

        elif cmd_lower.startswith("goto "):
            parts = cmd_lower.split()
            try:
                pan = float(parts[1])
                tilt = float(parts[2])
                zoom = float(parts[3]) if len(parts) > 3 else 0.0
                api.move_to(camera_id, pan, tilt, zoom)
                print(f"  Moving to pan={pan} tilt={tilt} zoom={zoom}")
            except (IndexError, ValueError):
                print("  Usage: goto <pan> <tilt> [zoom]")

        elif cmd_lower == "snap":
            url = api.trigger_snapshot(camera_id) if hasattr(api, 'trigger_snapshot') else None
            print(f"  Snapshot: {url or 'triggered (no URL returned)'}")
        elif cmd_lower == "stream":
            url = api.start_stream(camera_id)
            print(f"  Stream: {url or 'started (no URL returned)'}")
        elif cmd_lower == "night":
            api.toggle_night_vision(camera_id, True)
            print("  Night vision ON")
        elif cmd_lower == "nightoff":
            api.toggle_night_vision(camera_id, False)
            print("  Night vision OFF")
        elif cmd_lower == "privacy":
            api.toggle_privacy(camera_id, True)
            print("  Privacy mode ON (camera off)")
        elif cmd_lower == "privacyoff":
            api.toggle_privacy(camera_id, False)
            print("  Privacy mode OFF (camera active)")

        elif cmd_lower == "test":
            _ensure_stream()
            print("  Testing PTZ...")
            for label, x, y in [("RIGHT", 0.05, 0), ("LEFT", -0.05, 0),
                                 ("UP", 0, 0.05), ("DOWN", 0, -0.05)]:
                api.move(camera_id, pan=x, tilt=y)
                print(f"  {label}: sent")
                time.sleep(2)
            api.go_home(camera_id)
            print("  HOME: sent. Watch the live view!")

        elif is_arlo and cmd_lower.startswith("raw "):
            parts = cmd.split(maxsplit=3)
            if len(parts) < 4:
                print("  Usage: raw <action> <resource> <json>")
                continue
            try:
                props = json.loads(parts[3])
                result = api.send_raw(camera_id, parts[1], parts[2], props)
                print(f"  Result: {json.dumps(result, indent=2) if result else 'no response'}")
            except json.JSONDecodeError:
                print("  Error: Invalid JSON")

        elif cmd_lower in ("switch", "sw"):
            new_id = select_camera_generic(api, camera_id)
            if new_id != camera_id:
                _stop_stream()
                camera_id = new_id
                if config:
                    key = "camera_mac" if is_wyze else "camera_serial"
                    config[brand][key] = camera_id
                    save_config(config, config_path)
            print(f"  Now controlling: {api.cameras.get(camera_id, camera_id)}")

        elif cmd_lower in ("list", "ls", "cameras"):
            for cid, cam in api.cameras.items():
                marker = " <-- active" if cid == camera_id else ""
                print(f"  {cam}{marker}")

        elif cmd_lower in ("status", "info"):
            cam = api.cameras.get(camera_id)
            if cam:
                print(f"  Name:  {cam.name}")
                print(f"  Model: {cam.model}")
                print(f"  PTZ:   {cam.has_ptz}")
                print(f"  State: {cam.state}")
                print(f"  ID:    {cam.device_id}")
            print(f"  Brand: {brand}")
            print(f"  Step:  {step}")

        else:
            print(f"  Unknown: {cmd}")
            print("  w/a/s/d=move, +/-=zoom, h=home, switch=change camera, q=quit")

    print("\n  Disconnecting...")
    _stop_stream()
    api.close()
    print("  Done.\n")


def _run_interactive_local(ctrl, api):
    """Interactive control loop using local base station API (same as before)."""
    from controller import CameraController

    print("  === Controls ===")
    print("  Movement:    w/a/s/d    Zoom: +/-    Home: h    Stop: 0")
    print("  Speed: 1-9   Presets: p1-p9   Patterns: sweep, grid")
    print("  Quit: q")
    print("  " + "-" * 50)
    print()

    while True:
        try:
            cmd = input("  cam> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue
        if cmd in ("q", "quit", "exit"):
            break
        elif cmd in ("w", "up"):
            ctrl.up()
        elif cmd in ("s", "down"):
            ctrl.down()
        elif cmd in ("a", "left"):
            ctrl.left()
        elif cmd in ("d", "right"):
            ctrl.right()
        elif cmd in ("+", "z"):
            ctrl.zoom_in()
        elif cmd in ("-", "x"):
            ctrl.zoom_out()
        elif cmd in ("0", "stop"):
            ctrl.stop()
            print("  Stopped.")
        elif cmd in ("h", "home"):
            ctrl.home()
            print("  Home.")
        elif cmd in [str(i) for i in range(1, 10)]:
            ctrl.config.speed = int(cmd) / 10.0
            print(f"  Speed: {ctrl.config.speed}")
        elif cmd == "sweep":
            ctrl.sweep_horizontal()
        elif cmd == "grid":
            ctrl.grid_scan()
        else:
            print(f"  Unknown: {cmd}. w/a/s/d=move, q=quit")

    ctrl.stop()
    api.close()
    print("  Done.\n")


def cmd_move(args, config):
    """One-shot movement command (cloud mode)."""
    api = cloud_login(config, args.config)
    api.get_devices()

    camera_id = select_camera(
        api,
        getattr(args, 'camera', None) or config["arlo"]["camera_serial"],
    )

    api.start_event_stream()
    time.sleep(1)

    ccfg = config["control"]
    step = args.amount or 0.15

    move_map = {
        "left":    {"pan": -step},
        "right":   {"pan": step},
        "up":      {"tilt": step},
        "down":    {"tilt": -step},
        "zoomin":  {"zoom": step},
        "zoomout": {"zoom": -step},
        "home":    None,
    }

    direction = args.dir
    if direction == "home":
        api.go_home(camera_id)
        print(f"  Returning home.")
    elif direction in move_map:
        kwargs = move_map[direction]
        kwargs["speed"] = ccfg["move_speed"]
        kwargs["duration"] = ccfg["move_duration"]
        api.move(camera_id, **kwargs)
        print(f"  Moved: {direction}" + (f" ({step})" if args.amount else ""))
    else:
        print(f"  Unknown direction: {direction}")

    api.close()


def cmd_intercept(args, config):
    """MITM intercept for base station traffic analysis."""
    from interceptor import ARPInterceptor, CommandSniffer

    base_ip = getattr(args, 'base_ip', None) or config["arlo"]["base_station_ip"]
    if not base_ip:
        print("  Error: Base station IP required. Use --base-ip")
        sys.exit(1)

    interface = args.interface or config["network"]["interface"]
    capture_dir = config["intercept"]["capture_dir"]

    print("\n" + "=" * 60)
    print("  CamControl — Arlo Traffic Interceptor")
    print("=" * 60)
    print(f"  Target: {base_ip}")
    print(f"  Use the Arlo app to move the camera — we capture everything.")
    print("=" * 60 + "\n")

    interceptor = ARPInterceptor(base_station_ip=base_ip, interface=interface)

    def on_command(cmd):
        label = "PTZ" if cmd.is_ptz else "AUTH" if cmd.is_auth else "CMD"
        body_preview = f" | {json.dumps(cmd.body)[:80]}" if cmd.body else ""
        print(f"  [{label}] {cmd.method} {cmd.path}{body_preview}")

    sniffer = CommandSniffer(
        base_station_ip=base_ip, interface=interface,
        capture_dir=capture_dir, on_command=on_command,
    )

    def shutdown(sig=None, frame=None):
        print("\n  Stopping...")
        sniffer.stop()
        interceptor.stop()
        if sniffer.commands:
            path = sniffer.save_captures()
            print(f"  Saved {len(sniffer.commands)} commands to {path}")
        token = sniffer.get_latest_token()
        if token:
            config["arlo"]["auth_token"] = token
            save_config(config, args.config)
            print(f"  Token saved.")
        print(f"  Stats: {sniffer.stats}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    interceptor.start()
    time.sleep(1)
    sniffer.start()
    print("  Listening... (Ctrl+C to stop)\n")

    while True:
        time.sleep(5)
        s = sniffer.stats
        print(f"  [{time.strftime('%H:%M:%S')}] cmds={s['total_commands']} ptz={s['ptz_commands']} tokens={s['auth_tokens']}")


def cmd_replay(args, config):
    """Replay captured commands."""
    if not os.path.exists(args.capture_file):
        print(f"  Error: File not found: {args.capture_file}")
        sys.exit(1)

    with open(args.capture_file) as f:
        data = json.load(f)

    # Use cloud API for replay
    api = cloud_login(config, args.config)
    api.get_devices()
    api.start_event_stream()

    commands = data.get("ptz_commands", []) if args.ptz_only else data.get("all_commands", [])
    print(f"\n  Replaying {len(commands)} commands (delay={args.delay}s)...\n")

    for i, cmd in enumerate(commands):
        body = cmd.get("body", {})
        if body and body.get("resource"):
            camera_id = body.get("to", "")
            print(f"  [{i+1}/{len(commands)}] {body.get('action')} {body.get('resource')}")
            result = api.send_raw(
                camera_id,
                body.get("action", "set"),
                body.get("resource", ""),
                body.get("properties", {}),
            )
            if result:
                print(f"    -> {json.dumps(result)[:100]}")
        time.sleep(args.delay)

    print(f"\n  Replay complete.\n")
    api.close()


def main():
    parser = argparse.ArgumentParser(
        description="CamControl — Arlo Camera Hijacker & PTZ Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-c", "--config", default="config.yaml", help="Config file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument("-i", "--interface", default=None, help="Network interface")

    sub = parser.add_subparsers(dest="command", help="Command")

    # discover (requires sudo)
    p = sub.add_parser("discover", help="Find Arlo devices on LAN")
    p.add_argument("--subnet", help="Subnet to scan")
    p.add_argument("--base-ip", help="Known base station IP")
    p.add_argument("--save", action="store_true", help="Save to config")

    # cloud-login (Arlo)
    sub.add_parser("cloud-login", help="Authenticate with Arlo cloud")

    # wyze-login
    sub.add_parser("wyze-login", help="Authenticate with Wyze cloud")

    # wyze-bridge
    p = sub.add_parser("wyze-bridge", help="Manage docker-wyze-bridge")
    p.add_argument("action", choices=["start", "stop", "status"], help="Bridge action")

    # control
    p = sub.add_parser("control", help="Interactive PTZ control")
    p.add_argument("--brand", choices=["arlo", "wyze"], help="Camera brand")
    p.add_argument("--mode", choices=["cloud", "local"], help="Control mode (Arlo)")
    p.add_argument("--base-ip", help="Base station IP (Arlo local mode)")
    p.add_argument("--token", help="Auth token")
    p.add_argument("--camera", help="Camera device ID")

    # move (one-shot)
    p = sub.add_parser("move", help="One-shot camera movement")
    p.add_argument("--dir", required=True,
                    choices=["left", "right", "up", "down", "zoomin", "zoomout", "home"],
                    help="Direction")
    p.add_argument("--amount", type=float, help="Movement amount (0.0-1.0)")
    p.add_argument("--camera", help="Camera device ID")

    # intercept (requires sudo)
    p = sub.add_parser("intercept", help="MITM base station traffic")
    p.add_argument("--base-ip", help="Base station IP")

    # replay
    p = sub.add_parser("replay", help="Replay captured commands")
    p.add_argument("capture_file", help="Capture JSON file")
    p.add_argument("--delay", type=float, default=0.5, help="Delay between commands")
    p.add_argument("--ptz-only", action="store_true", help="Only PTZ commands")

    args = parser.parse_args()

    # Reset terminal to sane state (prevents ^M from prior runs)
    os.system("stty sane 2>/dev/null")

    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paho").setLevel(logging.WARNING)
    if args.verbose:
        logging.getLogger("arlo_cloud").setLevel(logging.INFO)

    config = load_config(args.config)
    if args.interface:
        config["network"]["interface"] = args.interface

    if not args.command:
        parser.print_help()
        sys.exit(1)

    dispatch = {
        "discover": cmd_discover,
        "cloud-login": cmd_cloud_login,
        "wyze-login": cmd_wyze_login,
        "wyze-bridge": cmd_wyze_bridge,
        "control": cmd_control,
        "move": cmd_move,
        "intercept": cmd_intercept,
        "replay": cmd_replay,
    }

    func = dispatch.get(args.command)
    if func:
        func(args, config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
