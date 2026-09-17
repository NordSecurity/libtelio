import pytest
from tests import config
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import new_connection_raw
from tests.utils.ping import ping


@pytest.mark.asyncio
@pytest.mark.android
async def test_android_emulator_connectivity() -> None:
    """Smoke test for the Android emulator integration (LLT-4138).

    Validates that nat-lab can execute commands on the guest and that the guest
    can reach a nat-lab service on the internet network (10.0.0.0/16).
    """
    async with new_connection_raw(ConnectionTag.VM_ANDROID_1) as connection:
        # Arbitrary command execution on the guest works.
        echo = await connection.create_process(["echo", "natlab"]).execute()
        assert "natlab" in echo.get_stdout()

        # Guest reaches the photo-album service on the nat-lab internet network.
        await ping(connection, config.PHOTO_ALBUM_IP, timeout=20)
