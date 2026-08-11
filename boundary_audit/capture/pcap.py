"""PCAP parser seam; tshark is authoritative on Linux."""

from pathlib import Path


def validate_capture(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0
