import pytest
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio_features import TelioFeatures, Direct

ALL_DIRECT_FEATURES = ["upnp", "local", "stun"]
EMPTY_PROVIDER = [""]


@pytest.mark.asyncio
async def test_default_direct_features() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [SetupParameters(features=TelioFeatures(direct=Direct(providers=None)))],
        )
        started_tasks = env.clients[0].get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" in started_tasks
        assert "StunEndpointProvider" in started_tasks


@pytest.mark.asyncio
async def test_enable_all_direct_features() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    features=TelioFeatures(direct=Direct(providers=ALL_DIRECT_FEATURES))
                )
            ],
        )
        started_tasks = env.clients[0].get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" in started_tasks
        assert "LocalInterfacesEndpointProvider" in started_tasks
        assert "StunEndpointProvider" in started_tasks


@pytest.mark.asyncio
async def test_check_features_with_empty_direct_providers() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    features=TelioFeatures(direct=Direct(providers=EMPTY_PROVIDER))
                )
            ],
        )
        started_tasks = env.clients[0].get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" not in started_tasks
        assert "StunEndpointProvider" not in started_tasks
