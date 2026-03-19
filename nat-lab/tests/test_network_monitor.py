import asyncio
import pytest
from contextlib import AsyncExitStack
from tests.helpers import setup_mesh_nodes, SetupParameters
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag, TargetOS

DEFAULT_WAITING_TIME = 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alpha_setup_params",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_SHARED_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_WINDOWS_1,
                adapter_type_override=TelioAdapterType.WINDOWS_NATIVE_TUN,
            ),
            marks=pytest.mark.windows,
        ),
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.VM_MAC,
                adapter_type_override=TelioAdapterType.NEP_TUN,
            ),
            marks=[
                pytest.mark.mac,
            ],
        ),
    ],
)
async def test_network_monitor(
    alpha_setup_params: SetupParameters,
) -> None:
    # 1 [interface creation] + 1 [set IP] + 1 [remove IP] + 1 [set IP] -> interface initialization + restart
    async with AsyncExitStack() as exit_stack:
        env = await setup_mesh_nodes(exit_stack, [alpha_setup_params])
        [client_alpha] = env.clients

        target_os = client_alpha.get_connection().target_os
        if target_os == TargetOS.Linux:
            NR_OF_NOTIFICATIONS = 12
            NOT_GREATER = True
        elif target_os == TargetOS.Windows:
            NR_OF_NOTIFICATIONS = 10
            NOT_GREATER = False
        else:
            NR_OF_NOTIFICATIONS = 4
            NOT_GREATER = True

        PLATFORM_AGNOSTIC_MESSAGE = "Detected network interface modification"

        await asyncio.sleep(DEFAULT_WAITING_TIME)
        await client_alpha.restart_interface()

        async def check_logs(msg, count):
            await client_alpha.wait_for_log(msg, count=count, not_greater=NOT_GREATER)

        await check_logs(PLATFORM_AGNOSTIC_MESSAGE, NR_OF_NOTIFICATIONS)

        if client_alpha.get_connection().target_os == TargetOS.Linux:
            PREFIX = "Received netfilter message: "
            LINK_NEW = f"{PREFIX}NewLink(LinkMessage "
            IPV4_IFADDR_NEW = f"{PREFIX}NewAddress(AddressMessage "
            IPV4_IFADDR_DEL = f"{PREFIX}DelAddress(AddressMessage "
            IPV4_ROUTE_NEW = f"{PREFIX}NewRoute(RouteMessage "
            IPV4_ROUTE_DEL = f"{PREFIX}DelRoute(RouteMessage "
            await check_logs(LINK_NEW, 4)
            await check_logs(IPV4_IFADDR_NEW, 2)
            await check_logs(IPV4_ROUTE_NEW, 4)
            await check_logs(IPV4_ROUTE_DEL, 1)
            await check_logs(IPV4_IFADDR_DEL, 1)
