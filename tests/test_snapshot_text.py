from dvinesoul_security.core.snapshot import SystemSnapshot
from dvinesoul_security.core.snapshot_text import snapshot_to_text


def test_snapshot_to_text_renders_system_data():
    snapshot = SystemSnapshot(
        system={
            "hostname": "test-host",
            "os": "Linux",
            "distribution": "Test Linux",
            "kernel": "6.0-test",
            "architecture": "x86_64",
            "python": "3.14.0",
            "cpu": "Test CPU",
            "cpu_count": "4",
            "uptime": "1h 2m",
            "ram_total": "6.0 GiB",
            "ram_available": "3.0 GiB",
            "swap_total": "6.0 GiB",
            "swap_used": "1.0 MiB",
            "disk_total": "452.0 GiB",
            "disk_used": "20.0 GiB",
            "disk_free": "410.0 GiB",
            "disk_used_percent": "5.0%",
        },
        processes=[],
        services=[],
        interfaces=[],
        connections=[],
        files=[],
    )

    output = snapshot_to_text(snapshot)

    assert "DVINESOUL SECURITY SYSTEM" in output
    assert "=== SYSTEM ===" in output
    assert "Hostname           : test-host" in output
    assert "=== CPU ===" in output
    assert "CPU                : Test CPU" in output
    assert "=== MEMORY ===" in output
    assert "RAM total          : 6.0 GiB" in output
    assert "=== STORAGE ===" in output
    assert "Disk used percent  : 5.0%" in output
    assert "=== PROCESSES ===" in output
    assert "Total processes    : 0" in output
    assert "=== SERVICES ===" in output
    assert "Total services     : 0" in output
    assert "=== NETWORK INTERFACES ===" in output
    assert "Total interfaces   : 0" in output
    assert "=== NETWORK CONNECTIONS ===" in output
    assert "Total sockets      : 0" in output
