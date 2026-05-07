from __future__ import annotations

from typing import List
from xml.etree import ElementTree

from routehawk.core.models import Asset


def import_nmap_xml(text: str) -> List[Asset]:
    root = ElementTree.fromstring(text)
    assets = []
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr") if address is not None else None
        hostnames = [
            item.get("name")
            for item in host.findall("./hostnames/hostname")
            if item.get("name")
        ]
        name = hostnames[0] if hostnames else ip
        if not name:
            continue
        ports = _open_ports(host)
        assets.append(
            Asset(
                host=name,
                scheme=_scheme_from_ports(ports),
                ip=ip,
                status=None,
                title=None,
                technologies=[f"tcp/{port}" for port in ports],
            )
        )
    return assets


def _open_ports(host) -> List[int]:
    ports = []
    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = port.get("portid")
        try:
            ports.append(int(port_id))
        except (TypeError, ValueError):
            continue
    return sorted(ports)


def _scheme_from_ports(ports: List[int]) -> str:
    if 443 in ports:
        return "https"
    return "http"
