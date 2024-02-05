import asyncio
import pytest
from contextlib import AsyncExitStack
from helpers import SetupParameters, setup_mesh_nodes
from telio import AdapterType, LinkState
from telio_features import TelioFeatures, LinkDetection, Wireguard
from utils import testing
from utils.connection_tracker import ConnectionLimits
from utils.connection_util import generate_connection_tracker_config, ConnectionTag
from utils.ping import Ping


def long_persistent_keepalive_periods() -> Wireguard:
    return Wireguard(proxying=3600, direct=3600, vpn=3600, stun=3600)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
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
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
            )
        ),
    ],
)
async def test_event_link_state_peers_idle_all_time(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients

        # Expect no link event while peers are idle
        await asyncio.sleep(20)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
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
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
            )
        )
    ],
)
async def test_event_link_state_peers_exchanging_data_for_a_long_time(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        for _ in range(0, 40):
            await asyncio.sleep(1)
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())
            async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

        # Expect no nolink event while peers are active
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
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
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
            )
        ),
    ],
)
async def test_event_link_state_peers_exchanging_data_then_idling(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        # Expect no link event while peers are idle
        await asyncio.sleep(30)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
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
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
            )
        ),
    ],
)
async def test_event_link_state_streaming_to_a_silent_peer(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, _ = [conn.connection for conn in env.connections]

        for _ in range(0, 15):
            await asyncio.sleep(1)
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await testing.wait_long(ping.wait_for_next_ping())

        await asyncio.sleep(10)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # There should be no detection in this case
        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        assert beta_events == [LinkState.Down, LinkState.Up]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
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
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
                features=TelioFeatures(
                    link_detection=LinkDetection(rtt_seconds=1),
                    wireguard=long_persistent_keepalive_periods(),
                ),
            )
        ),
    ],
)
async def test_event_link_state_peer_goes_offline(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await client_beta.stop_device()

        await asyncio.sleep(1)

        with pytest.raises(asyncio.TimeoutError):
            async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
                await testing.wait_normal(ping.wait_for_next_ping())

        await asyncio.sleep(15)
        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # 1 down when node is Connecting and 1 up when node is Connected
        assert alpha_events == [LinkState.Down, LinkState.Up]
        # beta will have 2 down events: 1 when is Connecting and 1 detected
        assert beta_events == [LinkState.Down, LinkState.Up, LinkState.Down]


# TODO: Add the scenario where peers exchange data then idle then resume
# For now, this scenario is flaky due to LLT-4753


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_1,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
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
                adapter_type=AdapterType.LinuxNativeWg,
                connection_tracker_config=generate_connection_tracker_config(
                    ConnectionTag.DOCKER_CONE_CLIENT_2,
                    derp_1_limits=ConnectionLimits(1, 1),
                ),
            )
        )
    ],
)
async def test_event_link_state_feature_disabled(
    alpha_setup_params: SetupParameters, beta_setup_params: SetupParameters
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(
            exit_stack, [alpha_setup_params, beta_setup_params]
        )
        alpha, beta = env.nodes
        client_alpha, client_beta = env.clients
        connection_alpha, connection_beta = [
            conn.connection for conn in env.connections
        ]

        async with Ping(connection_alpha, beta.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())
        async with Ping(connection_beta, alpha.ip_addresses[0]).run() as ping:
            await testing.wait_long(ping.wait_for_next_ping())

        await asyncio.sleep(30)

        alpha_events = client_beta.get_link_state_events(alpha.public_key)
        beta_events = client_alpha.get_link_state_events(beta.public_key)

        # There should be 2 node events Connecting and Connected
        # Both of them should have link_state field empty
        assert alpha_events == [None, None]
        assert beta_events == [None, None]
