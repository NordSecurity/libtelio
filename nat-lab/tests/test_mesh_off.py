import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio_features import TelioFeatures, Direct
from utils.connection_util import ConnectionTag


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                features=TelioFeatures(direct=Direct(providers=None)),
            )
        ),
    ],
)
@pytest.mark.parametrize(
    "beta_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                adapter_type=telio.AdapterType.LinuxNativeWg,
                features=TelioFeatures(direct=Direct(providers=None)),
            ),
        ),
    ],
)
async def test_mesh_off(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )

        client_alpha, _ = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        await client_alpha.set_mesh_off()

        # Checking if no peer is left after turning mesh net off
        # wg show outputs lines that start with the string "peer:" when any peer is present
        process = await connection_alpha.create_process([
            "wg",
            "show",
            "tun10",
        ]).execute()

        dig_stdout = process.get_stdout()

        assert (
            "peer:" not in dig_stdout.strip().split()
        ), f"There are leftover WireGuard peers after mesh is set to off: {dig_stdout}"
