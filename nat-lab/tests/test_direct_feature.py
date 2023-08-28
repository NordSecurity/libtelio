import pytest
import telio
from contextlib import AsyncExitStack
from mesh_api import API
from telio_features import TelioFeatures, Direct
from utils.connection_util import ConnectionTag, new_connection_by_tag

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
            telio.Client(
                alpha_connection,
                alpha,
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=None)),
            ).run(api.get_meshmap(alpha.id))
        )

        started_tasks = alpha_client.get_runtime().get_started_tasks()
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
            telio.Client(
                alpha_connection,
                alpha,
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(
                    direct=Direct(providers=ALL_DIRECT_FEATURES)
                ),
            ).run(api.get_meshmap(alpha.id))
        )

        started_tasks = alpha_client.get_runtime().get_started_tasks()
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
            telio.Client(
                alpha_connection,
                alpha,
                telio.AdapterType.BoringTun,
                telio_features=TelioFeatures(direct=Direct(providers=EMPTY_PROVIDER)),
            ).run(api.get_meshmap(alpha.id))
        )

        started_tasks = alpha_client.get_runtime().get_started_tasks()
        assert "UpnpEndpointProvider" not in started_tasks
        assert "LocalInterfacesEndpointProvider" not in started_tasks
        assert "StunEndpointProvider" not in started_tasks
