"""Stable evidence and experiment schemas.

The report is derived from these records; raw evidence is intentionally kept
alongside the normalized records in each immutable run directory.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NetworkMode(str, Enum):
    AIRGAP = "airgap"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class ActionCategory(str, Enum):
    LIFECYCLE = "lifecycle"
    STATE = "state"
    MOTION = "motion"
    PERCEPTION = "perception"
    DIAGNOSTICS = "diagnostics"
    SOFTWARE_UPDATE = "software_update"
    BACKGROUND = "background"


class ActionSpec(BaseModel):
    name: str
    category: ActionCategory
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = 5.0
    baseline_seconds: float = 1.0
    observation_seconds: float = 1.0
    cooldown_seconds: float = 0.2
    repeats: int = 1
    expected_status: int = 200


class Flow(BaseModel):
    flow_id: str
    ip_version: int
    transport_protocol: str
    dut_ip: str
    remote_ip: str
    dut_port: int
    remote_port: int
    first_seen: datetime
    last_seen: datetime
    duration_ms: float = 0.0
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    allowed: bool = True
    blocked: bool = False
    dns_names: List[str] = Field(default_factory=list)
    tls_server_names: List[str] = Field(default_factory=list)
    scenario_ids: List[str] = Field(default_factory=list)
    scope: str = "external"
    direct_ip: bool = False


class Event(BaseModel):
    type: str
    scenario_id: str
    timestamp: datetime
    monotonic_ms: float
    details: Dict[str, Any] = Field(default_factory=dict)


class DnsObservation(BaseModel):
    query_name: str
    query_type: str = "A"
    response_records: List[str] = Field(default_factory=list)
    timestamp: datetime
    client: str = "10.77.0.2"
    ttl: Optional[int] = None


class TlsObservation(BaseModel):
    flow_id: str
    timestamp: datetime
    tls_version: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_sans: List[str] = Field(default_factory=list)
    certificate_issuer: Optional[str] = None
    encrypted_payload: bool = True


class RunMetadata(BaseModel):
    tool_version: str
    backend: str
    mode: NetworkMode
    scenario: str
    command: str
    start: datetime
    end: Optional[datetime] = None
    random_seed: int = 1337
    simulator_version: str = "1.0"
    dut_ip: str = "10.77.0.2"
    gateway_ip: str = "10.77.0.1"

