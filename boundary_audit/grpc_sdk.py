"""gRPC control SDK for the black-box robotic OS simulator.

The service exposes only public control operations and capabilities. It does
not expose simulator internals, packet observations, or ground truth.
"""

import argparse
from concurrent import futures
from typing import Any, Dict, Optional

import grpc
from google.protobuf.json_format import MessageToDict
from google.protobuf.struct_pb2 import Struct

from .dut_simulator import DutSimulator
from .config import load_config
from .models import ActionCategory, ActionSpec
from .pydantic_compat import model_dump

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
    def __init__(self, dut: DutSimulator) -> None:
        self.dut = dut

    def health(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return model_dump(self.dut.health())

    def capabilities(self, request: Dict[str, Any]) -> Dict[str, Any]:
        return self.dut.get_capabilities()

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        category = ActionCategory(str(request.get("category", "background")))
        action = ActionSpec(name=str(request["action"]), category=category,
                            parameters=dict(request.get("parameters", {})))
        return model_dump(self.dut.execute(action))


def _handler(service: DutGrpcService, method: str) -> grpc.RpcMethodHandler:
    callback = getattr(service, method)
    return grpc.unary_unary_rpc_method_handler(
        lambda request, context: _response(callback(_decode(request))),
        request_deserializer=lambda value: value,
        response_serializer=lambda value: value,
    )


def add_dut_service(server: grpc.Server, dut: DutSimulator) -> None:
    service = DutGrpcService(dut)
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(SERVICE, {
        "Health": _handler(service, "health"),
        "Capabilities": _handler(service, "capabilities"),
        "Execute": _handler(service, "execute"),
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

    def health(self) -> Dict[str, Any]:
        return self._health({})

    def capabilities(self) -> Dict[str, Any]:
        return self._capabilities({})

    def execute(self, action: str, category: str = "background",
                parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._execute({"action": action, "category": category,
                              "parameters": parameters or {}})


def serve(dut: DutSimulator, bind: str = "0.0.0.0", port: int = 50051) -> grpc.Server:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    add_dut_service(server, dut)
    setattr(server, "bound_port", server.add_insecure_port("%s:%d" % (bind, port)))
    server.start()
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="DUT robotic OS gRPC control server")
    parser.add_argument("--bind")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-network", action="store_true")
    args = parser.parse_args()
    dut_config = load_config().get("dut", {})
    bind = args.bind or str(dut_config.get("grpc_bind", "0.0.0.0"))
    port = args.port or int(dut_config.get("grpc_port", 50051))
    dut = DutSimulator.from_config(network_enabled=not args.no_network)
    server = serve(dut, bind, port)
    print("DUT gRPC SDK listening on %s:%d" % (bind, port), flush=True)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(0)
    finally:
        dut.cleanup()


if __name__ == "__main__":
    main()
