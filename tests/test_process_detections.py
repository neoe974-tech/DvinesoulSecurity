from dvinesoul_security.core.processes import ProcessInfo
from dvinesoul_security.security.detections.processes import (
    detect_suspicious_process_locations,
)


def test_detects_process_from_suspicious_location():
    processes = [
        ProcessInfo(
            pid=1234,
            name="example",
            state="S",
            user="dvines",
            memory_kb=1024,
            executable="/tmp/example",
            command="/tmp/example",
        )
    ]

    findings = detect_suspicious_process_locations(processes)

    assert len(findings) == 1
    assert findings[0].category == "process"
    assert findings[0].severity == "medium"
    assert findings[0].is_observation is False


def test_normal_system_process_is_not_flagged():
    processes = [
        ProcessInfo(
            pid=1,
            name="systemd",
            state="S",
            user="root",
            memory_kb=1024,
            executable="/usr/lib/systemd/systemd",
            command="/sbin/init",
        )
    ]

    findings = detect_suspicious_process_locations(processes)

    assert findings == []
