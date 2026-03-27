import pytest
from tests.helpers import SetupParameters, Environment
from tests.utils.bindings import features_with_endpoint_providers, EndpointProvider
from typing import List

pytest_plugins = ["tests.helpers_fixtures"]

ALL_DIRECT_FEATURES = [
    EndpointProvider.UPNP,
    EndpointProvider.LOCAL,
    EndpointProvider.STUN,
]
EMPTY_PROVIDER: List[EndpointProvider] = []


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(features=features_with_endpoint_providers(None)),
        ),
    ],
)
@pytest.mark.asyncio
async def test_default_direct_features(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    alpha_client = env_mesh.clients[0]

    started_tasks = alpha_client.get_runtime().get_started_tasks()
    assert "UpnpEndpointProvider" not in started_tasks
    assert "LocalInterfacesEndpointProvider" in started_tasks
    assert "StunEndpointProvider" in started_tasks


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                features=features_with_endpoint_providers(ALL_DIRECT_FEATURES)
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_enable_all_direct_features(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    alpha_client = env_mesh.clients[0]

    started_tasks = alpha_client.get_runtime().get_started_tasks()
    assert "UpnpEndpointProvider" in started_tasks
    assert "LocalInterfacesEndpointProvider" in started_tasks
    assert "StunEndpointProvider" in started_tasks


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(features=features_with_endpoint_providers(EMPTY_PROVIDER)),
        ),
    ],
)
@pytest.mark.asyncio
async def test_check_features_with_empty_direct_providers(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    alpha_client = env_mesh.clients[0]

    started_tasks = alpha_client.get_runtime().get_started_tasks()
    assert "UpnpEndpointProvider" not in started_tasks
    assert "LocalInterfacesEndpointProvider" not in started_tasks
    assert "StunEndpointProvider" not in started_tasks
