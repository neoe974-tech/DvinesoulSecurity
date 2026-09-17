import json
import subprocess
import sys


def test_system_json_cli_output():
    result = subprocess.run(
        [sys.executable, "-m", "dvinesoul_security.cli", "system", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )

    data = json.loads(result.stdout)

    assert "risk_score" in data
    assert "security_findings" in data
    assert "observations" in data
    assert isinstance(data["security_findings"], list)
    assert isinstance(data["observations"], list)
    assert data["risk_score"] >= 0
