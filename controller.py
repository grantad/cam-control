"""
High-level camera controller that wraps the Arlo local API
with intuitive movement commands, directional control,
and automated movement patterns.
"""

import time
import logging
import threading
from typing import Optional
from dataclasses import dataclass

from arlo_api import ArloLocalAPI, PTZPosition

logger = logging.getLogger(__name__)


@dataclass
class MovementConfig:
    """PTZ movement parameters."""
    speed: float = 0.5          # 0.0 - 1.0
    step_size: float = 0.15     # How far each step moves (-1.0 to 1.0 scale)
    duration: float = 0.5       # How long each move command lasts (seconds)
    step_interval: float = 0.1  # Delay between continuous move steps


class CameraController:
    """
    High-level PTZ controller for an Arlo camera.
    Provides directional movement, scanning patterns,
    and continuous (joystick-like) control.
    """

    def __init__(
        self,
        api: ArloLocalAPI,
        camera_id: str,
        config: Optional[MovementConfig] = None,
    ):
        self.api = api
        self.camera_id = camera_id
        self.config = config or MovementConfig()

        self._continuous_running = False
        self._continuous_thread: Optional[threading.Thread] = None
        self._current_direction: Optional[str] = None

        # Position tracking (best-effort, may drift)
        self._position = PTZPosition()
        self._position_lock = threading.Lock()

    @property
    def camera(self):
        return self.api.cameras.get(self.camera_id)

    def refresh_position(self) -> Optional[PTZPosition]:
        """Query the camera for its current PTZ position."""
        pos = self.api.get_ptz_position(self.camera_id)
        if pos:
            with self._position_lock:
                self._position = pos
        return pos

    @property
    def position(self) -> PTZPosition:
        with self._position_lock:
            return self._position

    # === Directional Movement ===

    def left(self, amount: Optional[float] = None) -> bool:
        """Pan left."""
        step = amount or self.config.step_size
        return self.api.move(
            self.camera_id,
            pan=-step, tilt=0, zoom=0,
            speed=self.config.speed,
            duration=self.config.duration,
        )

    def right(self, amount: Optional[float] = None) -> bool:
        """Pan right."""
        step = amount or self.config.step_size
        return self.api.move(
            self.camera_id,
            pan=step, tilt=0, zoom=0,
            speed=self.config.speed,
            duration=self.config.duration,
        )

    def up(self, amount: Optional[float] = None) -> bool:
        """Tilt up."""
        step = amount or self.config.step_size
        return self.api.move(
            self.camera_id,
            pan=0, tilt=step, zoom=0,
            speed=self.config.speed,
            duration=self.config.duration,
        )

    def down(self, amount: Optional[float] = None) -> bool:
        """Tilt down."""
        step = amount or self.config.step_size
        return self.api.move(
            self.camera_id,
            pan=0, tilt=-step, zoom=0,
            speed=self.config.speed,
            duration=self.config.duration,
        )

    def zoom_in(self, amount: Optional[float] = None) -> bool:
        """Zoom in."""
        step = amount or self.config.step_size
        return self.api.move(
            self.camera_id,
            pan=0, tilt=0, zoom=step,
            speed=self.config.speed,
            duration=self.config.duration,
        )

    def zoom_out(self, amount: Optional[float] = None) -> bool:
        """Zoom out."""
        step = amount or self.config.step_size
        return self.api.move(
            self.camera_id,
            pan=0, tilt=0, zoom=-step,
            speed=self.config.speed,
            duration=self.config.duration,
        )

    def home(self) -> bool:
        """Return to home position."""
        return self.api.go_home(self.camera_id)

    def stop(self) -> bool:
        """Stop any current movement."""
        self._stop_continuous()
        return self.api.stop_move(self.camera_id)

    def look_at(self, pan: float, tilt: float, zoom: float = 0.0) -> bool:
        """Move to an absolute position."""
        return self.api.move_to(
            self.camera_id,
            pan=pan, tilt=tilt, zoom=zoom,
            speed=self.config.speed,
        )

    # === Continuous Movement (hold-to-move) ===

    def start_continuous(self, direction: str):
        """
        Start continuous movement in a direction.
        Keeps sending move commands until stop_continuous is called.

        direction: "left", "right", "up", "down", "zoom_in", "zoom_out"
        """
        self._stop_continuous()

        move_map = {
            "left":     (-self.config.step_size, 0, 0),
            "right":    (self.config.step_size, 0, 0),
            "up":       (0, self.config.step_size, 0),
            "down":     (0, -self.config.step_size, 0),
            "zoom_in":  (0, 0, self.config.step_size),
            "zoom_out": (0, 0, -self.config.step_size),
            # Diagonals
            "up_left":    (-self.config.step_size, self.config.step_size, 0),
            "up_right":   (self.config.step_size, self.config.step_size, 0),
            "down_left":  (-self.config.step_size, -self.config.step_size, 0),
            "down_right": (self.config.step_size, -self.config.step_size, 0),
        }

        if direction not in move_map:
            logger.error(f"Unknown direction: {direction}")
            return

        pan, tilt, zoom = move_map[direction]
        self._current_direction = direction
        self._continuous_running = True

        def loop():
            while self._continuous_running:
                self.api.move(
                    self.camera_id,
                    pan=pan, tilt=tilt, zoom=zoom,
                    speed=self.config.speed,
                    duration=self.config.step_interval * 2,
                )
                time.sleep(self.config.step_interval)

        self._continuous_thread = threading.Thread(
            target=loop, daemon=True, name=f"continuous-{direction}"
        )
        self._continuous_thread.start()
        logger.info(f"Continuous move: {direction}")

    def _stop_continuous(self):
        """Stop continuous movement."""
        if self._continuous_running:
            self._continuous_running = False
            if self._continuous_thread:
                self._continuous_thread.join(timeout=2)
            self._current_direction = None

    # === Automated Patterns ===

    def sweep_horizontal(
        self,
        sweep_range: float = 0.8,
        steps: int = 10,
        pause: float = 0.5,
    ) -> bool:
        """
        Sweep the camera left to right and back.
        Useful for scanning a wide area.
        """
        step_size = (sweep_range * 2) / steps

        logger.info(f"Horizontal sweep: range={sweep_range}, steps={steps}")

        # Sweep right
        for i in range(steps):
            if not self.api.move(
                self.camera_id, pan=step_size, tilt=0, zoom=0,
                speed=self.config.speed, duration=0.3,
            ):
                return False
            time.sleep(pause)

        # Sweep back left
        for i in range(steps):
            if not self.api.move(
                self.camera_id, pan=-step_size, tilt=0, zoom=0,
                speed=self.config.speed, duration=0.3,
            ):
                return False
            time.sleep(pause)

        return True

    def sweep_vertical(
        self,
        sweep_range: float = 0.5,
        steps: int = 6,
        pause: float = 0.5,
    ) -> bool:
        """Sweep the camera up and down."""
        step_size = (sweep_range * 2) / steps

        logger.info(f"Vertical sweep: range={sweep_range}, steps={steps}")

        for i in range(steps):
            if not self.api.move(
                self.camera_id, pan=0, tilt=step_size, zoom=0,
                speed=self.config.speed, duration=0.3,
            ):
                return False
            time.sleep(pause)

        for i in range(steps):
            if not self.api.move(
                self.camera_id, pan=0, tilt=-step_size, zoom=0,
                speed=self.config.speed, duration=0.3,
            ):
                return False
            time.sleep(pause)

        return True

    def grid_scan(
        self,
        h_range: float = 0.8,
        v_range: float = 0.5,
        h_steps: int = 5,
        v_steps: int = 3,
        pause: float = 1.0,
    ) -> bool:
        """
        Scan a grid pattern — sweep horizontally at each vertical position.
        Great for systematically covering an entire room or yard.
        """
        h_step = (h_range * 2) / h_steps
        v_step = (v_range * 2) / v_steps

        logger.info(
            f"Grid scan: {h_steps}x{v_steps} "
            f"({h_steps * v_steps} positions, ~{h_steps * v_steps * pause:.0f}s)"
        )

        # Start at top-left
        self.look_at(pan=-h_range, tilt=v_range)
        time.sleep(1)

        for row in range(v_steps):
            # Alternate sweep direction (serpentine)
            if row % 2 == 0:
                # Left to right
                for col in range(h_steps):
                    self.api.move(
                        self.camera_id, pan=h_step, tilt=0, zoom=0,
                        speed=self.config.speed * 0.5, duration=0.3,
                    )
                    time.sleep(pause)
            else:
                # Right to left
                for col in range(h_steps):
                    self.api.move(
                        self.camera_id, pan=-h_step, tilt=0, zoom=0,
                        speed=self.config.speed * 0.5, duration=0.3,
                    )
                    time.sleep(pause)

            # Move down one row
            if row < v_steps - 1:
                self.api.move(
                    self.camera_id, pan=0, tilt=-v_step, zoom=0,
                    speed=self.config.speed * 0.5, duration=0.3,
                )
                time.sleep(0.5)

        logger.info("Grid scan complete")
        return True

    def track_direction(self, direction: str, distance: float = 0.3) -> bool:
        """
        Quick directional nudge — for tracking something that moved.
        """
        moves = {
            "left":  (-distance, 0, 0),
            "right": (distance, 0, 0),
            "up":    (0, distance, 0),
            "down":  (0, -distance, 0),
        }
        if direction not in moves:
            return False

        pan, tilt, zoom = moves[direction]
        return self.api.move(
            self.camera_id,
            pan=pan, tilt=tilt, zoom=zoom,
            speed=1.0,  # Max speed for tracking
            duration=0.2,
        )

    # === Presets ===

    def save_preset(self, preset_id: int, name: str = "") -> bool:
        """Save current position as a preset."""
        return self.api.set_preset(self.camera_id, preset_id, name)

    def goto_preset(self, preset_id: int) -> bool:
        """Move to a saved preset."""
        return self.api.go_to_preset(self.camera_id, preset_id)

    def patrol(self, preset_ids: Optional[list[int]] = None) -> bool:
        """Start patrol between presets."""
        return self.api.start_patrol(self.camera_id, preset_ids)

    def stop_patrol(self) -> bool:
        """Stop patrol."""
        return self.api.stop_patrol(self.camera_id)

    # === Info ===

    @property
    def status(self) -> dict:
        return {
            "camera_id": self.camera_id,
            "camera": str(self.camera) if self.camera else "unknown",
            "has_ptz": self.camera.has_ptz if self.camera else False,
            "position": str(self.position),
            "continuous_direction": self._current_direction,
            "speed": self.config.speed,
            "step_size": self.config.step_size,
        }
