import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters
from tests.utils.bindings import default_features, TelioAdapterType
from tests.utils.command_grepper import CommandGrepper
from tests.utils.connection import ConnectionTag, Connection, TargetOS
from tests.utils.multicast import MulticastClient, MulticastServer
from tests.utils.process import ProcessExecError
from tests.utils.router import IPProto, get_ip_address_type
from typing import List, Optional, Tuple

MULTICAST_ROUTE_CHECK_TIMEOUT_S: float = 30.0

# netsh reports a missing route with either of these, depending on the adapter.
NO_SUCH_ROUTE_MESSAGES = [
    "Element not found.",
    "The filename, directory name, or volume label syntax is incorrect.",
]


def generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, TelioAdapterType]],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type_override=adapter_type,
            features=default_features(enable_multicast=True),
        )
        for conn_tag, adapter_type in cfg
    ]


MUILTICAST_TEST_PARAMS = [
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
        marks=pytest.mark.fullcone,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "mdns",
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
        marks=pytest.mark.windows,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.VM_WINDOWS_1, TelioAdapterType.WINDOWS_NATIVE_TUN),
        ]),
        "mdns",
        marks=pytest.mark.windows,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.VM_MAC, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
        marks=pytest.mark.mac,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.VM_MAC, TelioAdapterType.NEP_TUN),
        ]),
        "mdns",
        marks=pytest.mark.mac,
    ),
]


async def add_multicast_route(
    connection: Connection, interface_name: Optional[str] = None
) -> None:
    if connection.target_os == TargetOS.Linux:
        ipconf = connection.create_process(
            ["ip", "route", "add", "224.0.0.0/4", "dev", "tun10"]
        )
        await ipconf.execute()
    elif connection.target_os == TargetOS.Mac:
        ipconf = await connection.create_process(
            ["route", "delete", "224.0.0.0/4"]
        ).execute()
        ipconf = await connection.create_process(
            ["route", "add", "-net", "224.0.0.0/4", "-interface", "utun10"]
        ).execute()
    elif connection.target_os == TargetOS.Windows:
        # Windows resolves the outgoing interface for multicast via the routing
        # table. Without this route the two lab NICs are metric-tied and the
        # choice is unstable, so multicast can leave through the wrong one and
        # never reach the meshnet adapter. LLT-7699.
        assert interface_name
        try:
            await connection.create_process(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    "224.0.0.0/4",
                    interface_name,
                ],
                quiet=True,
            ).execute()
        except ProcessExecError as exception:
            output = f"{exception.stdout}\n{exception.stderr}"
            # Both messages mean "there was no such route", which is fine here.
            if not any(msg in output for msg in NO_SUCH_ROUTE_MESSAGES):
                raise exception

        try:
            await connection.create_process(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    "224.0.0.0/4",
                    interface_name,
                ],
                quiet=True,
            ).execute()
        except ProcessExecError as exception:
            if (
                "The object already exists."
                not in f"{exception.stdout}\n{exception.stderr}"
            ):
                raise exception

        grepper = CommandGrepper(
            connection,
            ["netsh", "interface", "ipv4", "show", "route"],
            timeout=MULTICAST_ROUTE_CHECK_TIMEOUT_S,
        )
        if not await grepper.check_exists("224.0.0.0/4", [interface_name]):
            raise Exception(
                "Failed to create ipv4 multicast route; route table: "
                f"{grepper.get_stdout()}"
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, protocol", MUILTICAST_TEST_PARAMS)
async def test_multicast(setup_params: List[SetupParameters], protocol: str) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)

        alpha, beta = env.nodes

        alpha_ip = [
            ip for ip in alpha.ip_addresses if get_ip_address_type(ip) == IPProto.IPv4
        ][0]
        beta_ip = [
            ip for ip in beta.ip_addresses if get_ip_address_type(ip) == IPProto.IPv4
        ][0]

        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        client_alpha, client_beta = env.clients

        await add_multicast_route(
            alpha_connection, client_alpha.get_router().get_interface_name()
        )
        await add_multicast_route(
            beta_connection, client_beta.get_router().get_interface_name()
        )

        async with MulticastServer(
            beta_connection, protocol, None, beta_ip
        ).run() as server:
            await server.wait_till_ready()
            await MulticastClient(alpha_connection, protocol, None, alpha_ip).execute()


MUILTICAST_DISALLOWED_TEST_PARAMS = [
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_FULLCONE_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "ssdp",
        marks=pytest.mark.fullcone,
    ),
    pytest.param(
        generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_1, TelioAdapterType.NEP_TUN),
            (ConnectionTag.DOCKER_SYMMETRIC_CLIENT_2, TelioAdapterType.NEP_TUN),
        ]),
        "mdns",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, protocol", MUILTICAST_DISALLOWED_TEST_PARAMS)
async def test_multicast_disallowed(
    setup_params: List[SetupParameters], protocol: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)

        alpha_connection, beta_connection = [
            conn.connection for conn in env.connections
        ]

        client_alpha, client_beta = env.clients

        alpha, beta = env.nodes

        alpha_ip = [
            ip for ip in alpha.ip_addresses if get_ip_address_type(ip) == IPProto.IPv4
        ][0]
        beta_ip = [
            ip for ip in beta.ip_addresses if get_ip_address_type(ip) == IPProto.IPv4
        ][0]

        mesh_config_alpha = env.api.get_meshnet_config(alpha.id)
        if mesh_config_alpha.peers is not None:
            for peer in mesh_config_alpha.peers:
                if peer.base.hostname == beta.hostname:
                    peer.allow_multicast = False
        await client_alpha.set_meshnet_config(mesh_config_alpha)

        mesh_config_beta = env.api.get_meshnet_config(beta.id)
        if mesh_config_beta.peers is not None:
            for peer in mesh_config_beta.peers:
                if peer.base.hostname == alpha.hostname:
                    peer.peer_allows_multicast = False
        await client_beta.set_meshnet_config(mesh_config_beta)

        await add_multicast_route(
            alpha_connection, client_alpha.get_router().get_interface_name()
        )
        await add_multicast_route(
            beta_connection, client_beta.get_router().get_interface_name()
        )

        async with MulticastServer(
            beta_connection, protocol, None, beta_ip
        ).run() as server:
            with pytest.raises(ProcessExecError):
                await server.wait_till_ready()
                await MulticastClient(
                    alpha_connection, protocol, 10, alpha_ip
                ).execute()
