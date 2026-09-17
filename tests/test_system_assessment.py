from dvinesoul_security.core.snapshot import SystemSnapshot
from dvinesoul_security.core.services import ServiceInfo
from dvinesoul_security.network.connections import ConnectionInfo
from dvinesoul_security.network.interfaces import InterfaceInfo
from dvinesoul_security.security.assessment import calculate_risk_score
from dvinesoul_security.security.system_assessment import assess_system


def empty_snapshot(
    *,
    services=None,
    connections=None,
    interfaces=None,
):
    return SystemSnapshot(
        system={},
        processes=[],
        services=services or [],
        interfaces=interfaces or [],
        connections=connections or [],
        files=[],
    )


def test_assess_system_detects_failed_service():
    snapshot = empty_snapshot(
        services=[
            ServiceInfo(
                name="example.service",
                load="loaded",
                active="failed",
                sub="failed",
                description="Example failed service",
            )
        ]
    )

    findings = assess_system(snapshot)

    assert len(findings) == 1
    assert findings[0].category == "service"
    assert findings[0].severity == "high"
    assert findings[0].title == "Failed system service detected"
    assert findings[0].is_observation is False
    assert "example.service" in findings[0].detail


def test_assess_system_detects_listening_socket_as_observation():
    snapshot = empty_snapshot(
        connections=[
            ConnectionInfo(
                protocol="tcp",
                state="LISTEN",
                local="0.0.0.0:22",
                remote="*:*",
                process="sshd",
            )
        ]
    )

    findings = assess_system(snapshot)

    assert len(findings) == 1
    assert findings[0].category == "network"
    assert findings[0].severity == "info"
    assert findings[0].title == "Listening network socket detected"
    assert findings[0].is_observation is True
    assert "0.0.0.0:22" in findings[0].detail
    assert "sshd" in findings[0].detail


def test_assess_system_detects_established_connection_as_observation():
    snapshot = empty_snapshot(
        connections=[
            ConnectionInfo(
                protocol="tcp",
                state="ESTAB",
                local="192.0.2.10:50000",
                remote="198.51.100.20:443",
                process="example-client",
            )
        ]
    )

    findings = assess_system(snapshot)

    assert len(findings) == 1
    assert findings[0].category == "network"
    assert findings[0].severity == "info"
    assert findings[0].title == "Established network connection detected"
    assert findings[0].is_observation is True
    assert "198.51.100.20:443" in findings[0].detail


def test_assess_system_detects_interface_errors():
    snapshot = empty_snapshot(
        interfaces=[
            InterfaceInfo(
                name="eth0",
                state="up",
                mac="00:11:22:33:44:55",
                ipv4="192.0.2.10",
                ipv6="",
                rx_bytes=1000,
                tx_bytes=1000,
                rx_packets=10,
                tx_packets=10,
                rx_errors=2,
                tx_errors=1,
                rx_dropped=3,
                tx_dropped=4,
            )
        ]
    )

    findings = assess_system(snapshot)

    assert len(findings) == 1
    assert findings[0].category == "network"
    assert findings[0].severity == "low"
    assert findings[0].title == "Network interface errors detected"
    assert findings[0].is_observation is False
    assert "eth0" in findings[0].detail


def test_assess_system_observations_do_not_increase_risk_score():
    snapshot = empty_snapshot(
        connections=[
            ConnectionInfo(
                protocol="tcp",
                state="ESTAB",
                local="192.0.2.10:50000",
                remote="198.51.100.20:443",
                process="example-client",
            ),
            ConnectionInfo(
                protocol="tcp",
                state="LISTEN",
                local="0.0.0.0:22",
                remote="*:*",
                process="sshd",
            ),
        ]
    )

    findings = assess_system(snapshot)

    assert len(findings) == 2
    assert all(finding.is_observation for finding in findings)
    assert calculate_risk_score(findings) == 0
