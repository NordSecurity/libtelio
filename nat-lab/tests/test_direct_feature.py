from contextlib import AsyncExitStack

import pytest
import telio
from mesh_api import API
from telio_features import TelioFeatures, Direct
from utils import ConnectionTag, new_connection_by_tag

ALL_DIRECT_FEATURES = ["upnp", "local", "stun"]
EMPTY_PROVIDER = [""]


@pytest.mark.asyncio
async def test_default_direct_features() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, _) = api.default_config_two_nodes()

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=None)),
            )
        )

        started_tasks = alpha_client._events._runtime._started_tasks
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" in started_tasks
        assert "StunEndpointProvider" in started_tasks


@pytest.mark.asyncio
async def test_enable_all_direct_features() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, _) = api.default_config_two_nodes()

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=ALL_DIRECT_FEATURES)
                ),
            )
        )

        started_tasks = alpha_client._events._runtime._started_tasks
        assert "UpnpEndpointProvider" in started_tasks
        assert "LocalInterfacesEndpointProvider" in started_tasks
        assert "StunEndpointProvider" in started_tasks


@pytest.mark.asyncio
async def test_check_features_with_empty_direct_providers() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()
        (alpha, _) = api.default_config_two_nodes()

        alpha_connection = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_UPNP_CLIENT_1)
        )

        alpha_client = await exit_stack.enter_async_context(
            telio.run_meshnet(
                alpha_connection,
                alpha,
                api.get_meshmap(alpha.id),
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=EMPTY_PROVIDER)),
            )
        )

        started_tasks = alpha_client._events._runtime._started_tasks
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" not in started_tasks
        assert "StunEndpointProvider" not in started_tasks
