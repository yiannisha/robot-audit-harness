"""gRPC control SDK for the black-box robotic OS simulator.

The service exposes only public control operations and capabilities. It does
not expose simulator internals, packet observations, or ground truth.
"""

import argparse
import base64
import time
import uuid
from concurrent import futures
from pathlib import Path
from typing import Any, Dict, Optional

import grpc
from google.protobuf.json_format import MessageToDict
from google.protobuf.struct_pb2 import Struct

from .dut_simulator import DutSimulator
from .config import load_config
from .models import ActionCategory, ActionSpec
from .pydantic_compat import model_dump
from .monitoring import MonitoringAgent

SERVICE = "boundary_audit.Dut"


def _request(value: Dict[str, Any]) -> bytes:
    message = Struct()
    message.update(value)
    return message.SerializeToString()


def _response(value: Dict[str, Any]) -> bytes:
    message = Struct()
    message.update(value)
    return message.SerializeToString()


def _decode(value: bytes) -> Dict[str, Any]:
    message = Struct()
    message.ParseFromString(value)
    return MessageToDict(message, preserving_proto_field_name=True)


class DutGrpcService:
    def __init__(self, dut: DutSimulator, monitor_root: Path = Path("runs"),
                 monitor_interface: str = "any", monitor_packet_limit: int = 100000) -> None:
        self.dut = dut
        self.monitor = MonitoringAgent(monitor_root, monitor_interface, monitor_packet_limit)

    def health(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return model_dump(self.dut.health())

    def capabilities(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self.dut.get_capabilities()

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        category = ActionCategory(str(request.get("category", "background")))
        action = ActionSpec(name=str(request["action"]), category=category,
                            parameters=dict(request.get("parameters", {})))
        started = time.time()
        result = model_dump(self.dut.execute(action))
        if self.monitor.session and self.monitor.session.started:
            self.monitor.session.record_api({"request_id": uuid.uuid4().hex, "action": action.name,
                                             "category": action.category.value, "parameters": action.parameters,
                                             "started_epoch": started, "ended_epoch": time.time(),
                                             "result": result})
        return result

    def start_monitor(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self.monitor.start(str(request.get("scenario", "remote")), str(request.get("mode", "observe")),
                                  dict(request.get("metadata", {})))

    def mark_event(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self.monitor.mark_event(str(request["type"]), str(request.get("scenario_id", "unattributed")),
                                       dict(request.get("details", {})))

    def stop_monitor(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self.monitor.stop(bool(request.get("cancelled", False)))

    def monitor_status(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self.monitor.status()

    def get_artifact(self, request: Dict[str, Any]) -> Dict[str, Any]:
        name = str(request["name"])
        data = self.monitor.artifact(name)
        return {"name": name, "data_base64": base64.b64encode(data).decode("ascii"), "bytes": len(data)}


def _handler(service: DutGrpcService, method: str) -> grpc.RpcMethodHandler:
    callback = getattr(service, method)
    return grpc.unary_unary_rpc_method_handler(
        lambda request, context: _response(callback(_decode(request))),
        request_deserializer=lambda value: value,
        response_serializer=lambda value: value,
    )


def add_dut_service(server: grpc.Server, dut: DutSimulator, monitor_root: Path = Path("runs"),
                    monitor_interface: str = "any", monitor_packet_limit: int = 100000) -> None:
    service = DutGrpcService(dut, monitor_root, monitor_interface, monitor_packet_limit)
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(SERVICE, {
        "Health": _handler(service, "health"),
        "Capabilities": _handler(service, "capabilities"),
        "Execute": _handler(service, "execute"),
        "StartMonitor": _handler(service, "start_monitor"),
        "MarkEvent": _handler(service, "mark_event"),
        "StopMonitor": _handler(service, "stop_monitor"),
        "MonitorStatus": _handler(service, "monitor_status"),
        "GetArtifact": _handler(service, "get_artifact"),
    }),))


class DutGrpcClient:
    """Client SDK usable by a controller on any reachable host."""

    def __init__(self, target: str, channel: Optional[grpc.Channel] = None) -> None:
        self._channel = channel or grpc.insecure_channel(target)
        self._health = self._channel.unary_unary(
            "/%s/Health" % SERVICE, request_serializer=_request, response_deserializer=_decode)
        self._capabilities = self._channel.unary_unary(
            "/%s/Capabilities" % SERVICE, request_serializer=_request,
            response_deserializer=_decode)
        self._execute = self._channel.unary_unary(
            "/%s/Execute" % SERVICE, request_serializer=_request, response_deserializer=_decode)
        self._start_monitor = self._channel.unary_unary(
            "/%s/StartMonitor" % SERVICE, request_serializer=_request, response_deserializer=_decode)
        self._mark_event = self._channel.unary_unary(
            "/%s/MarkEvent" % SERVICE, request_serializer=_request, response_deserializer=_decode)
        self._stop_monitor = self._channel.unary_unary(
            "/%s/StopMonitor" % SERVICE, request_serializer=_request, response_deserializer=_decode)
        self._monitor_status = self._channel.unary_unary(
            "/%s/MonitorStatus" % SERVICE, request_serializer=_request, response_deserializer=_decode)
        self._get_artifact = self._channel.unary_unary(
            "/%s/GetArtifact" % SERVICE, request_serializer=_request, response_deserializer=_decode)

    def health(self) -> Dict[str, Any]:
        return self._health({})

    def capabilities(self) -> Dict[str, Any]:
        return self._capabilities({})

    def execute(self, action: str, category: str = "background",
                parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._execute({"action": action, "category": category,
                              "parameters": parameters or {}})

    def start_monitor(self, scenario: str = "remote", mode: str = "observe",
                      metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._start_monitor({"scenario": scenario, "mode": mode, "metadata": metadata or {}})

    def mark_event(self, event_type: str, scenario_id: str = "unattributed",
                   details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._mark_event({"type": event_type, "scenario_id": scenario_id, "details": details or {}})

    def stop_monitor(self, cancelled: bool = False) -> Dict[str, Any]:
        return self._stop_monitor({"cancelled": cancelled})

    def monitor_status(self) -> Dict[str, Any]:
        return self._monitor_status({})

    def get_artifact(self, name: str) -> bytes:
        return base64.b64decode(self._get_artifact({"name": name})["data_base64"])


def serve(dut: DutSimulator, bind: str = "0.0.0.0", port: int = 50051,
          monitor_root: Path = Path("runs"), monitor_interface: str = "any",
          monitor_packet_limit: int = 100000) -> grpc.Server:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    add_dut_service(server, dut, monitor_root, monitor_interface, monitor_packet_limit)
    setattr(server, "bound_port", server.add_insecure_port("%s:%d" % (bind, port)))
    server.start()
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="DUT robotic OS gRPC control server")
    parser.add_argument("--bind")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-network", action="store_true")
    parser.add_argument("--monitor-interface", default="any")
    parser.add_argument("--monitor-root", default="runs")
    parser.add_argument("--monitor-packet-limit", type=int, default=100000)
    args = parser.parse_args()
    dut_config = load_config().get("dut", {})
    bind = args.bind or str(dut_config.get("grpc_bind", "0.0.0.0"))
    port = args.port or int(dut_config.get("grpc_port", 50051))
    dut = DutSimulator.from_config(network_enabled=not args.no_network)
    server = serve(dut, bind, port, Path(args.monitor_root), args.monitor_interface,
                   args.monitor_packet_limit)
    print("DUT gRPC SDK listening on %s:%d" % (bind, port), flush=True)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(0)
    finally:
        dut.cleanup()


if __name__ == "__main__":
    main()
