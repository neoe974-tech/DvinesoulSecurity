from pathlib import Path

from dvinesoul_security.core.files import inventory_directory, inspect_file


def test_inspect_file_returns_metadata(tmp_path: Path):
    target = tmp_path / "example.txt"
    target.write_text("Dvinesoul Security test")

    info = inspect_file(target)

    assert info is not None
    assert info.path == str(target)
    assert info.file_type == "file"
    assert info.size > 0
    assert info.modified_ns > 0
    assert len(info.sha256) == 64


def test_missing_file_returns_none(tmp_path: Path):
    target = tmp_path / "missing.txt"

    assert inspect_file(target) is None


def test_inventory_directory(tmp_path: Path):
    (tmp_path / "one.txt").write_text("one")
    (tmp_path / "two.txt").write_text("two")

    results = inventory_directory(tmp_path)

    assert len(results) == 2
    assert results[0].path < results[1].path
    assert all(item.file_type == "file" for item in results)
