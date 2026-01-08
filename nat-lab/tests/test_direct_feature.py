import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters
from tests.utils.bindings import features_with_endpoint_providers, EndpointProvider
from tests.utils.testing import log_test_passed
from typing import List

ALL_DIRECT_FEATURES = [
    EndpointProvider.UPNP,
    EndpointProvider.LOCAL,
    EndpointProvider.STUN,
]
EMPTY_PROVIDER: List[EndpointProvider] = []


@pytest.mark.asyncio
async def test_default_direct_features() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [SetupParameters(features=features_with_endpoint_providers(None))],
        )
        started_tasks = env.clients[0].get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" in started_tasks
        assert "StunEndpointProvider" in started_tasks
        log_test_passed()


@pytest.mark.asyncio
async def test_enable_all_direct_features() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    features=features_with_endpoint_providers(ALL_DIRECT_FEATURES)
                )
            ],
        )
        started_tasks = env.clients[0].get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" in started_tasks
        assert "LocalInterfacesEndpointProvider" in started_tasks
        assert "StunEndpointProvider" in started_tasks
        log_test_passed()


@pytest.mark.asyncio
async def test_check_features_with_empty_direct_providers() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    features=features_with_endpoint_providers(EMPTY_PROVIDER)
                )
            ],
        )
        started_tasks = env.clients[0].get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" not in started_tasks
        assert "StunEndpointProvider" not in started_tasks
        log_test_passed()
