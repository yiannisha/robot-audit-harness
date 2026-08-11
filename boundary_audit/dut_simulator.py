"""Black-box robotic OS simulator.

This module models the software running on a robot, rather than the robot's
physical hardware.  It deliberately exposes no audit evidence or ground
truth.  Actions use ordinary local transport and, when enabled, ordinary
network sockets so an observer outside this process can discover behaviour.
"""

import json
import argparse
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set

from .device import ActionResult, DeviceAdapter, HealthResult
from .models import ActionCategory, ActionSpec
from .config import load_config


ALL_ACTIONS: Set[str] = {
    "baseline",
    "power_off", "boot", "initial_network_join", "idle_30s", "idle_5min",
    "reboot", "shutdown", "read_robot_state", "read_joint_state", "read_imu",
    "read_battery", "read_firmware_version", "read_service_state", "stand",
    "lie_down", "move_forward", "move_backward", "strafe", "rotate",
    "velocity_control", "attitude_control", "trajectory_follow", "special_motion",
    "camera_open", "camera_stream", "camera_stop", "microphone_start",
    "microphone_stop", "lidar_start", "lidar_stop", "state_stream_start",
    "state_stream_stop", "mapping_start", "mapping_stop", "localization_start",
    "set_goal", "navigation_start", "navigation_stop", "obstacle_avoidance_enable",
    "obstacle_avoidance_disable", "set_volume", "play_audio", "tts", "led_set",
    "voice_service_start", "subscribe_lowstate", "subscribe_imu",
    "send_motor_position", "send_motor_velocity", "send_motor_torque",
}


@dataclass(frozen=True)
class ServiceEndpoint:
    """A real endpoint used by a simulated robot service."""

    host: str
    port: int
    protocol: str = "tcp"
    tls: bool = False
    payload_bytes: int = 128


@dataclass
class RobotState:
    power: str = "off"
    posture: str = "unknown"
    motion: str = "stopped"
    network: str = "offline"
    services: Dict[str, str] = field(default_factory=dict)
    sensor_streams: Set[str] = field(default_factory=set)


DEFAULT_ENDPOINTS: Mapping[str, ServiceEndpoint] = {
    "time_sync": ServiceEndpoint("pool.ntp.org", 123, "udp", False, 48),
    "discovery": ServiceEndpoint("example.com", 443, "tcp", True, 128),
    "authentication": ServiceEndpoint("example.com", 443, "tcp", True, 256),
    "updates": ServiceEndpoint("example.com", 443, "tcp", True, 256),
    "telemetry": ServiceEndpoint("example.com", 443, "tcp", True, 192),
}


class DutSimulator(DeviceAdapter):
    """A machine-agnostic, capability-driven robotic operating system."""

    def __init__(self, capabilities: Optional[Iterable[str]] = None,
                 endpoints: Optional[Mapping[str, ServiceEndpoint]] = None,
                 network_enabled: bool = True, local_port: int = 7447) -> None:
        self.capabilities = set(capabilities or ALL_ACTIONS)
        self.endpoints = dict(endpoints or DEFAULT_ENDPOINTS)
        self.network_enabled = network_enabled
        self.local_port = local_port
        self.state = RobotState()
        self.calls = 0

    @classmethod
    def from_config(cls, config: Optional[Mapping[str, Any]] = None,
                    network_enabled: Optional[bool] = None) -> "DutSimulator":
        raw = dict((config or load_config()).get("dut", {}))
        configured = raw.get("capabilities", "all")
        capabilities = None if configured == "all" else configured
        endpoints = {
            name: ServiceEndpoint(
                host=str(value["host"]), port=int(value["port"]),
                protocol=str(value.get("protocol", "tcp")),
                tls=bool(value.get("tls", False)),
                payload_bytes=int(value.get("payload_bytes", 128)),
            )
            for name, value in raw.get("endpoints", {}).items()
        }
        return cls(capabilities=capabilities, endpoints=endpoints or None,
                   network_enabled=raw.get("network_enabled", True)
                   if network_enabled is None else network_enabled,
                   local_port=int(raw.get("local_port", 7447)))

    def reset(self) -> None:
        self.calls = 0
        self.state = RobotState()

    def health(self) -> HealthResult:
        return HealthResult(ok=True, detail="robot operating system ready")

    def get_capabilities(self) -> Dict[str, Any]:
        return {"actions": sorted(self.capabilities), "services": sorted(self.state.services)}

    def execute(self, action: ActionSpec) -> ActionResult:
        self.calls += 1
        if action.name not in self.capabilities:
            return ActionResult(ok=False, status_code=404, detail="unsupported action",
                                response={"action": action.name, "supported": False})
        errors: List[str] = []
        try:
            self._local_command(action)
            self._apply_state(action)
            for service in self._services_for(action.name):
                try:
                    self._call_service(service)
                except OSError as error:
                    errors.append("%s: %s" % (service, error))
        except (ValueError, RuntimeError) as error:
            return ActionResult(ok=False, status_code=409, detail=str(error),
                                response={"action": action.name})
        return ActionResult(ok=True, status_code=200, detail="action executed",
                            response={"action": action.name, "network_errors": errors})

    def cleanup(self) -> None:
        self.state.sensor_streams.clear()
        self.state.services.clear()

    def _local_command(self, action: ActionSpec) -> None:
        if not self.network_enabled:
            return
        message = json.dumps({"topic": "robot.command", "action": action.name,
                              "parameters": action.parameters}).encode("utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message, ("127.0.0.1", self.local_port))

    def _apply_state(self, action: ActionSpec) -> None:
        name = action.name
        if name in ("boot", "reboot"):
            self.state.power, self.state.network = "on", "joining"
        elif name == "initial_network_join":
            self.state.network = "online"
        elif name in ("power_off", "shutdown"):
            self.state.power, self.state.network = "off", "offline"
        elif name == "stand":
            self.state.posture = "standing"
        elif name == "lie_down":
            self.state.posture = "lying"
        elif name in {"move_forward", "move_backward", "strafe", "rotate",
                      "velocity_control", "attitude_control", "trajectory_follow",
                      "special_motion"}:
            self.state.motion = name
        elif name.endswith("_start") and name in {"camera_stream", "microphone_start",
                                                   "lidar_start", "state_stream_start",
                                                   "mapping_start", "navigation_start",
                                                   "voice_service_start"}:
            self.state.sensor_streams.add(name[:-6])
        elif name.endswith("_stop"):
            self.state.sensor_streams.discard(name[:-5])

    def _services_for(self, action: str) -> List[str]:
        if action in ("boot", "reboot"):
            return ["time_sync", "discovery", "authentication", "updates", "telemetry"]
        if action == "initial_network_join":
            return ["discovery", "authentication"]
        if action in ("idle_30s", "idle_5min", "read_service_state"):
            return ["telemetry"]
        if action in ("camera_stream", "microphone_start", "voice_service_start"):
            return ["telemetry"]
        return []

    def _call_service(self, name: str) -> None:
        endpoint = self.endpoints.get(name)
        if endpoint is None or not self.network_enabled:
            return
        addresses = socket.getaddrinfo(endpoint.host, endpoint.port, type=socket.SOCK_DGRAM
                                       if endpoint.protocol == "udp" else socket.SOCK_STREAM)
        family, socktype, _, _, address = addresses[0]
        with socket.socket(family, socktype) as sock:
            sock.settimeout(5.0)
            if endpoint.protocol == "udp":
                sock.sendto(b"boundary-audit robot service %s" % name.encode("ascii"), address)
                return
            connection: Any = sock
            if endpoint.tls:
                context = ssl.create_default_context()
                connection = context.wrap_socket(sock, server_hostname=endpoint.host)
            with connection:
                connection.connect(address)
                connection.sendall(("GET /robot/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                                    % (name, endpoint.host)).encode("ascii"))
                connection.recv(1)

    def _public_action(self, name: str, category: ActionCategory,
                       parameters: Optional[Dict[str, Any]] = None) -> ActionResult:
        return self.execute(ActionSpec(name=name, category=category,
                                       parameters=parameters or {}))

    def stand(self) -> ActionResult:
        return self._public_action("stand", ActionCategory.MOTION)

    def lie_down(self) -> ActionResult:
        return self._public_action("lie_down", ActionCategory.MOTION)

    def velocity_control(self, velocity: float) -> ActionResult:
        return self._public_action("velocity_control", ActionCategory.MOTION,
                                   {"velocity": velocity})

    def camera_open(self) -> ActionResult:
        return self._public_action("camera_open", ActionCategory.PERCEPTION)

    def camera_stream(self) -> ActionResult:
        return self._public_action("camera_stream", ActionCategory.PERCEPTION)

    def camera_stop(self) -> ActionResult:
        return self._public_action("camera_stop", ActionCategory.PERCEPTION)


def main() -> None:
    """Run the DUT as a small line-oriented control process.

    Input is JSON lines containing ``action``, ``category`` and optional
    ``parameters``.  This is a control surface only; network observation is
    still performed by the machine or gateway running outside this process.
    """
    parser = argparse.ArgumentParser(description="black-box robotic OS simulator")
    parser.add_argument("--no-network", action="store_true")
    args = parser.parse_args()
    dut = DutSimulator(network_enabled=not args.no_network)
    print(json.dumps({"health": dut.health().dict(), "capabilities": dut.get_capabilities()}), flush=True)
    try:
        import sys
        for line in sys.stdin:
            request = json.loads(line)
            action = ActionSpec(name=str(request["action"]),
                                category=ActionCategory(request.get("category", "background")),
                                parameters=request.get("parameters", {}))
            print(dut.execute(action).json(), flush=True)
    finally:
        dut.cleanup()


if __name__ == "__main__":
    main()
