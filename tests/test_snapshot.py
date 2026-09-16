from dvinesoul_security.core.snapshot import (
    SystemSnapshot,
    collect_system_snapshot,
)


def test_collect_system_snapshot():
    snapshot = collect_system_snapshot()

    assert isinstance(snapshot, SystemSnapshot)

    assert isinstance(snapshot.system, dict)
    assert isinstance(snapshot.processes, list)
    assert isinstance(snapshot.services, list)
    assert isinstance(snapshot.interfaces, list)
    assert isinstance(snapshot.connections, list)

    assert "hostname" in snapshot.system
    assert "os" in snapshot.system
    assert "kernel" in snapshot.system
