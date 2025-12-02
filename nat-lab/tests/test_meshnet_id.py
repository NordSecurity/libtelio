import pytest
import re
from contextlib import AsyncExitStack
from tests.helpers import SetupParameters, setup_environment
from tests.utils.bindings import default_features, TelioAdapterType
from tests.utils.connection import ConnectionTag


@pytest.mark.asyncio
async def test_meshnet_id_generated_only_when_meshnet_starts() -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_setup_params = SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            adapter_type_override=TelioAdapterType.NEP_TUN,
            features=default_features(
                enable_nurse=True,
                enable_lana=("path.db", False),
            ),
            is_meshnet=False,
        )

        env = await exit_stack.enter_async_context(
            setup_environment(
                exit_stack,
                [alpha_setup_params],
            )
        )

        [client_alpha] = env.clients
        # Wait for everything to get set up
        await client_alpha.wait_for_log("Telio::start_named: Ok(())")

        logs = await client_alpha.get_log()
        # There should be no meshnet ID generation
        assert logs.count("Meshnet ID:") == 0

        config = env.api.get_meshnet_config(env.nodes[0].id)
        await client_alpha.set_meshnet_config(config)

        await client_alpha.wait_for_log("Meshnet ID:")

        logs = await client_alpha.get_log()
        assert re.search(
            r"Meshnet ID: Some\(([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)",
            logs,
        )
