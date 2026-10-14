import pytest
from pathlib import Path
from tests import log_collector
from tests.utils.connection import Connection, TargetOS
from unittest.mock import AsyncMock, Mock


@pytest.mark.utils
async def test_save_windows_registry_snapshot(monkeypatch, tmp_path) -> None:
    export_process = Mock()
    export_process.execute = AsyncMock()
    cleanup_process = Mock()
    cleanup_process.execute = AsyncMock()

    connection = Mock(spec=Connection)
    connection.target_os = TargetOS.Windows
    connection.create_process = Mock(side_effect=[export_process, cleanup_process])

    async def download_snapshot(remote_path, local_path):
        assert remote_path == log_collector.WINDOWS_REGISTRY_SNAPSHOT_ARCHIVE
        Path(local_path).write_bytes(b"registry snapshot")

    connection.download = AsyncMock(side_effect=download_snapshot)
    monkeypatch.setattr(
        log_collector, "get_current_test_log_path", lambda: str(tmp_path)
    )

    await log_collector.save_windows_registry_snapshot(connection)

    export_command = connection.create_process.call_args_list[0].args[0][-1]
    for hive in log_collector.WINDOWS_REGISTRY_HIVES:
        assert hive in export_command
    assert (tmp_path / "windows_registry.zip").is_file()
    export_process.execute.assert_awaited_once()
    cleanup_process.execute.assert_awaited_once()
