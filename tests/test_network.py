from __future__ import annotations

import subprocess

import pytest

from scanner.web import network


def test_parse_nmap_xml_extracts_open_services() -> None:
    xml_output = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" />
            <service name="ssh" product="OpenSSH" version="9.0" />
          </port>
          <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack" />
            <service name="https" product="nginx" version="1.25" />
          </port>
          <port protocol="tcp" portid="25">
            <state state="closed" reason="reset" />
            <service name="smtp" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    services = network._parse_nmap_xml(xml_output)

    assert services == [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "reason": "syn-ack",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "9.0",
            "extrainfo": "",
        },
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "reason": "syn-ack",
            "service": "https",
            "product": "nginx",
            "version": "1.25",
            "extrainfo": "",
        },
    ]


def test_scan_runs_nmap_and_returns_services(monkeypatch) -> None:
    xml_output = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="3306">
            <state state="open" reason="syn-ack" />
            <service name="mysql" product="MySQL" version="8.0" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout=xml_output, stderr="")

    monkeypatch.setattr(network.subprocess, "run", fake_run)

    result = network.scan("https://example.com")

    assert result["host"] == "example.com"
    assert result["services"][0]["port"] == 3306
    assert result["services"][0]["service"] == "mysql"


def test_run_nmap_raises_when_binary_missing(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(network.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="Docker is not installed"):
        network._run_nmap("example.com")
