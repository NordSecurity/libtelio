import asyncio
import pytest
from contextlib import asynccontextmanager, AsyncExitStack
from tests.helpers import SetupParameters, ping_between_all_nodes, setup_mesh_nodes
from tests.mesh_api import API
from tests.utils.bindings import (
    default_features,
    features_with_endpoint_providers,
    EndpointProvider,
    TelioAdapterType,
)
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import get_libtelio_binary_path
from tests.utils.logger import log
from tests.utils.output_notifier import OutputNotifier
from tests.utils.router.windows_router import WindowsRouter
from typing import AsyncIterator, List


def _generate_setup_parameters(
    conn_tags: List[ConnectionTag],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type_override=TelioAdapterType.BORING_TUN,
            features=default_features(),
            fingerprint=f"{conn_tag}",
        )
        for conn_tag in conn_tags
    ]


async def test_start_with_tun() -> None:
    setup_params = _generate_setup_parameters([
        ConnectionTag.DOCKER_CONE_CLIENT_1,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
    ])

    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client, _ = env.clients
        alpha, _ = env.nodes

        await ping_between_all_nodes(env)
        await alpha_client.stop_device()
        tun = await alpha_client.create_tun(11)
        await alpha_client.start_with_tun(tun, "tun11")
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        await ping_between_all_nodes(env)


@pytest.mark.parametrize(
    "alpha_tag",
    [
        pytest.param(ConnectionTag.VM_MAC, marks=pytest.mark.mac),
        pytest.param(ConnectionTag.DOCKER_CONE_CLIENT_1),
    ],
)
async def test_start_with_tun_and_switch_it_at_runtime(alpha_tag) -> None:
    setup_params = _generate_setup_parameters([
        alpha_tag,
        ConnectionTag.DOCKER_CONE_CLIENT_2,
    ])

    tun_name_prefix = "utun" if alpha_tag == ConnectionTag.VM_MAC else "tun"

    async with AsyncExitStack() as exit_stack:

        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha_client, _ = env.clients
        alpha, _ = env.nodes

        await alpha_client.stop_device()

        tun11 = await alpha_client.create_tun(11)
        await alpha_client.start_with_tun(tun11, tun_name_prefix + "11")
        alpha_client.get_router().set_interface_name(tun_name_prefix + "11")
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha.id))
        await alpha_client.get_router().delete_interface(tun_name_prefix + "10")
        await ping_between_all_nodes(env)

        tun12 = await alpha_client.create_tun(12)
        await alpha_client.get_proxy().set_tun(tun12)
        await alpha_client.restart_interface(new_name=tun_name_prefix + "12")
        await alpha_client.get_router().delete_interface(tun_name_prefix + "11")
        await ping_between_all_nodes(env)


@pytest.mark.windows
async def test_start_named_ext_if_filter() -> None:
    async with AsyncExitStack() as exit_stack:

        @asynccontextmanager
        async def start_tcli(node, conn, router) -> AsyncIterator:
            output_notifier = OutputNotifier()
            started_event = asyncio.Event()
            output_notifier.notify_output(
                "started telio with WindowsNativeWg", started_event
            )

            async def on_stdout_stderr(output):
                log.info("[%s]: stdout: %s", node.name, output)
                await output_notifier.handle_output(output)

            client = await exit_stack.enter_async_context(
                conn.create_process([
                    get_libtelio_binary_path("tcli.exe", conn),
                    "--less-spam",
                    '-f { "paths": { "priority": ["relay"]} }',
                ]).run(on_stdout_stderr, on_stdout_stderr)
            )
            await client.wait_stdin_ready()

            try:
                await client.escape_and_write_stdin([
                    "dev",
                    "start",
                    "wireguard-nt",
                    router.get_interface_name(),
                    str(node.private_key),
                ])
                await started_event.wait()
                yield
            finally:
                await client.escape_and_write_stdin(["dev", "stop"])

        api = API()
        ext_if_filter = []
        fake_node = api.default_config_one_node()
        fake_node.name = "fake_alpha"

        env = await setup_mesh_nodes(
            exit_stack,
            [
                SetupParameters(
                    connection_tag=ConnectionTag.VM_WINDOWS_1,
                    features=features_with_endpoint_providers([EndpointProvider.STUN]),
                ),
                SetupParameters(
                    connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                    features=features_with_endpoint_providers([EndpointProvider.STUN]),
                ),
            ],
        )

        alpha_conn = env.connections[0].connection
        alpha_client, *_ = env.clients
        alpha_node, *_ = env.nodes

        curr_interface_name = alpha_client.get_router().get_interface_name() + "_0"
        fake_router = WindowsRouter(alpha_conn, fake_node.ip_stack, curr_interface_name)
        ext_if_filter.append(fake_router.get_interface_name())
        await exit_stack.enter_async_context(
            start_tcli(fake_node, alpha_conn, fake_router)
        )
        await fake_router.setup_interface(fake_node.ip_addresses)
        await fake_router.create_fake_ipv4_route("0.0.0.0/0")

        await alpha_client.stop_device()
        await alpha_client.start_named_ext_if_filter(
            alpha_client.get_router().get_interface_name(), ext_if_filter
        )
        await alpha_client.set_meshnet_config(env.api.get_meshnet_config(alpha_node.id))

        # Wait for direct stun connections and wait for logs from windows.rs
        await asyncio.gather(*[
            alpha_client.wait_for_log(f"Interface {interface} is not default!")
            for interface in ext_if_filter
        ])
