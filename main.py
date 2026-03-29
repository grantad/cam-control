#!/usr/bin/env python3
"""
CamControl — Arlo Camera Hijacker & PTZ Controller

Control your Arlo camera without the Arlo app.
Supports both direct-WiFi cameras (cloud API) and base station setups (local API).

Usage:
    python main.py discover                        # Find Arlo devices on LAN
    python main.py cloud-login                     # Auth with Arlo cloud (direct-WiFi cameras)
    python main.py control                         # Interactive PTZ control (auto-detects mode)
    python main.py control --mode cloud            # Force cloud mode
    python main.py control --mode local --base-ip X  # Force local base station mode
    python main.py move --dir left                 # One-shot movement
    python main.py intercept --base-ip <IP>        # MITM to capture base station commands
    python main.py replay <capture_file>           # Replay captured commands

Discovery requires root/sudo. Cloud mode does NOT require sudo.
"""

import os
import sys
import signal
import time
import argparse
import logging
import json
import getpass
from typing import Optional

import yaml

from discovery import discover_arlo_devices, print_devices, get_subnet
from arlo_cloud import ArloCloudAPI

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
    """Interactive PTZ control — works in cloud or local mode."""
    mode = getattr(args, 'mode', None) or config["arlo"].get("mode", "cloud")

    print("\n" + "=" * 60)
    print(f"  CamControl — Interactive Camera Control ({mode} mode)")
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
    """Interactive control loop using cloud API."""
    speed = ccfg["move_speed"]
    step = 0.15
    duration = ccfg["move_duration"]

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

        # Movement
        elif cmd_lower in ("w", "up"):
            api.move(camera_id, tilt=step, speed=speed, duration=duration)
        elif cmd_lower in ("s", "down"):
            api.move(camera_id, tilt=-step, speed=speed, duration=duration)
        elif cmd_lower in ("a", "left"):
            api.move(camera_id, pan=-step, speed=speed, duration=duration)
        elif cmd_lower in ("d", "right"):
            api.move(camera_id, pan=step, speed=speed, duration=duration)
        elif cmd_lower in ("+", "z", "zi", "zoomin"):
            api.move(camera_id, zoom=step, speed=speed, duration=duration)
        elif cmd_lower in ("-", "x", "zo", "zoomout"):
            api.move(camera_id, zoom=-step, speed=speed, duration=duration)

        # Diagonals
        elif cmd_lower in ("wa", "upleft"):
            api.move(camera_id, pan=-step, tilt=step, speed=speed, duration=duration)
        elif cmd_lower in ("wd", "upright"):
            api.move(camera_id, pan=step, tilt=step, speed=speed, duration=duration)
        elif cmd_lower in ("sa", "downleft"):
            api.move(camera_id, pan=-step, tilt=-step, speed=speed, duration=duration)
        elif cmd_lower in ("sd", "downright"):
            api.move(camera_id, pan=step, tilt=-step, speed=speed, duration=duration)

        # Stop / Home
        elif cmd_lower in ("0", "stop"):
            api.stop_move(camera_id)
            print("  Stopped.")
        elif cmd_lower in ("h", "home"):
            api.go_home(camera_id)
            print("  Returning home.")

        # Speed
        elif cmd_lower in [str(i) for i in range(1, 10)]:
            speed = int(cmd_lower) / 10.0
            print(f"  Speed: {speed}")

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
            print("  Sweeping...")
            for _ in range(8):
                api.move(camera_id, pan=0.2, speed=speed, duration=0.3)
                time.sleep(0.5)
            for _ in range(8):
                api.move(camera_id, pan=-0.2, speed=speed, duration=0.3)
                time.sleep(0.5)
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
                api.move_to(camera_id, pan, tilt, zoom, speed)
                print(f"  Moving to pan={pan} tilt={tilt} zoom={zoom}")
            except (IndexError, ValueError):
                print("  Usage: goto <pan> <tilt> [zoom]")

        # Camera functions
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

        # Raw command
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

        # Info
        # Switch camera
        elif cmd_lower in ("switch", "sw"):
            new_id = select_camera(api, camera_id, force_pick=True)
            if new_id != camera_id:
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
            print(f"  Speed: {speed}")

        else:
            print(f"  Unknown: {cmd}")
            print("  w/a/s/d=move, +/-=zoom, h=home, switch=change camera, q=quit")

    print("\n  Disconnecting...")
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

    # cloud-login
    sub.add_parser("cloud-login", help="Authenticate with Arlo cloud")

    # control
    p = sub.add_parser("control", help="Interactive PTZ control")
    p.add_argument("--mode", choices=["cloud", "local"], help="Control mode")
    p.add_argument("--base-ip", help="Base station IP (local mode)")
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

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    config = load_config(args.config)
    if args.interface:
        config["network"]["interface"] = args.interface

    if not args.command:
        parser.print_help()
        sys.exit(1)

    dispatch = {
        "discover": cmd_discover,
        "cloud-login": cmd_cloud_login,
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
