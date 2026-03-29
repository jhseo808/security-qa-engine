from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # Shared Address Space
]


def validate_url(url: str) -> None:
    """URL이 안전한지 검증. 내부 IP/사설망 접근 시 ValueError 발생."""
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"지원하지 않는 스키마: '{parsed.scheme}'. http 또는 https만 허용됩니다.")

    host = parsed.hostname
    if not host:
        raise ValueError("유효하지 않은 URL: 호스트를 찾을 수 없습니다.")

    # localhost 직접 차단
    if host.lower() in ("localhost", "local"):
        raise ValueError(f"내부 호스트 접근 차단: '{host}'")

    # DNS 해석 후 IP 검사
    try:
        addr_infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"DNS 해석 실패: '{host}' — {e}") from e

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        for network in BLOCKED_NETWORKS:
            if ip in network:
                raise ValueError(
                    f"내부 IP 접근 차단: '{host}' → {ip} ({network}). "
                    "허가된 외부 도메인만 스캔할 수 있습니다."
                )
