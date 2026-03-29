from __future__ import annotations

import subprocess
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree


def scan(url: str) -> dict[str, Any]:
    host = _extract_host(url)
    xml_output = _run_nmap(host)
    return {
        "host": host,
        "services": _parse_nmap_xml(xml_output),
    }


def _extract_host(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Could not extract host from URL: {url}")
    return host


_NMAP_IMAGE = "instrumentisto/nmap"


def _run_nmap(host: str) -> str:
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                _NMAP_IMAGE,
                "-Pn",
                "-T4",
                "-sV",
                "--top-ports", "200",
                host,
                "-oX", "-",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Docker is not installed or not available in PATH.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"nmap scan timed out for host: {host}") from error

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(stderr or f"nmap exited with code {result.returncode}")

    return result.stdout


def _parse_nmap_xml(xml_output: str) -> list[dict[str, Any]]:
    if not xml_output.strip():
        return []

    root = ElementTree.fromstring(xml_output)
    services: list[dict[str, Any]] = []

    for host_node in root.findall("host"):
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue

            service_node = port_node.find("service")
            services.append(
                {
                    "port": int(port_node.get("portid", "0")),
                    "protocol": port_node.get("protocol", "tcp"),
                    "state": state_node.get("state", ""),
                    "reason": state_node.get("reason", ""),
                    "service": _service_name(service_node),
                    "product": (service_node.get("product", "") if service_node is not None else ""),
                    "version": (service_node.get("version", "") if service_node is not None else ""),
                    "extrainfo": (service_node.get("extrainfo", "") if service_node is not None else ""),
                }
            )

    services.sort(key=lambda item: (item["port"], item["protocol"]))
    return services


def _service_name(service_node) -> str:
    if service_node is None:
        return "unknown"
    return service_node.get("name", "unknown") or "unknown"
