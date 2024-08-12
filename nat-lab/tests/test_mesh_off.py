import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import PathType, State
from telio_features import TelioFeatures, Direct, LinkDetection
from timeouts import TEST_MESH_STATE_AFTER_DISCONNECTING_NODE_TIMEOUT
from utils.connection_util import ConnectionTag
from utils.ping import ping


# Marks in-tunnel stack only, exiting only through IPv4
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "direct",
    [True, False],
)
async def test_mesh_off(direct) -> None:
    async with AsyncExitStack() as exit_stack:
        features = (
            TelioFeatures(direct=Direct(providers=None))
            if direct
            else TelioFeatures(direct=None)
        )
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    adapter_type=telio.AdapterType.LinuxNativeWg,
                    features=features,
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    adapter_type=telio.AdapterType.LinuxNativeWg,
                    features=features,
                ),
            ],
        )
        alpha, beta = env.nodes

        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await client_alpha.set_mesh_off()

        # Checking if no peer is left after turning mesh net off
        # wg show outputs lines that start with the string "peer:" when any peer is present
        process = await connection_alpha.create_process([
            "wg",
            "show",
            "tun10",
        ]).execute()

        wg_show_stdout = process.get_stdout()

        assert (
            "peer:" not in wg_show_stdout.strip().split()
        ), f"There are leftover WireGuard peers after mesh is set to off: {wg_show_stdout}"

        path_type = PathType.Direct if direct else PathType.Relay

        await client_alpha.wait_for_state_peer(
            beta.public_key, [State.Disconnected], [path_type]
        )

        await client_alpha.set_meshmap(env.api.get_meshmap(alpha.id))

        asyncio.gather(
            client_alpha.wait_for_state_peer(
                beta.public_key, [State.Connected], [path_type]
            ),
            client_beta.wait_for_state_peer(
                alpha.public_key, [State.Connected], [path_type]
            ),
        )

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )
        client_beta.allow_errors(
            ["telio_proxy::proxy.*Unable to send. WG Address not available"]
        )


@pytest.mark.asyncio
@pytest.mark.timeout(TEST_MESH_STATE_AFTER_DISCONNECTING_NODE_TIMEOUT)
async def test_mesh_state_after_disconnecting_node() -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    features=TelioFeatures(
                        direct=Direct(providers=["stun", "local", "upnp"]),
                        link_detection=LinkDetection(rtt_seconds=5),
                    ),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_2,
                    features=TelioFeatures(
                        direct=Direct(providers=["stun", "local", "upnp"]),
                        link_detection=LinkDetection(rtt_seconds=5),
                    ),
                ),
            ],
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        await ping(connection_alpha, beta.ip_addresses[0])
        await ping(connection_beta, alpha.ip_addresses[0])

        await client_beta.stop_device()

        await client_alpha.wait_for_state_peer(
            beta.public_key, [State.Connecting], list(PathType)
        )

        with pytest.raises(asyncio.TimeoutError):
            await client_alpha.wait_for_state_peer(
                beta.public_key, [State.Connected], list(PathType), timeout=15
            )

        await client_beta.simple_start()
        await client_beta.set_meshmap(env.api.get_meshmap(beta.id))

        await client_alpha.wait_for_state_peer(
            beta.public_key, [State.Connected], [PathType.Direct]
        )

        # LLT-5532: To be cleaned up...
        client_alpha.allow_errors(
            ["boringtun::noise::timers.*CONNECTION_EXPIRED\\(REKEY_ATTEMPT_TIME\\)"]
        )
        client_beta.allow_errors(
            ["boringtun::noise::timers.*CONNECTION_EXPIRED\\(REKEY_ATTEMPT_TIME\\)"]
        )
