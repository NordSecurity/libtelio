import asyncio
import pytest
from tests.helpers import SetupParameters, Environment
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
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env_mesh: Environment,
) -> None:
    # 1 [interface creation] + 1 [set IP] + 1 [remove IP] + 1 [set IP] -> interface initialization + restart
    env = env_mesh
    [client_alpha] = env.clients

    target_os = client_alpha.get_connection().target_os
    if target_os == TargetOS.Linux:
        NR_OF_NOTIFICATIONS = 12
        NOT_GREATER = True
    elif target_os == TargetOS.Windows:
        # Notifications for each of IPv4 and IPv6:
        # disable: 2 parameter changes + 1 interface removed
        # enable: 1 interface added + 2 parameter changes (before Connected=true)
        NR_OF_NOTIFICATIONS = 12
        NOT_GREATER = False
    else:
        NR_OF_NOTIFICATIONS = 4
        NOT_GREATER = True

    PLATFORM_AGNOSTIC_MESSAGE = "Detected network interface modification"
    # Logged by the Windows monitor for an interface that is up
    WIN_CONNECTED = "Connected=true"

    await asyncio.sleep(DEFAULT_WAITING_TIME)
    if target_os == TargetOS.Windows:
        # Count only notifications caused by disable/enable, not by adapter creation
        logs_before = await client_alpha.log.get()
        notifications_before = logs_before.count(PLATFORM_AGNOSTIC_MESSAGE)
        connected_before = logs_before.count(WIN_CONNECTED)
        await client_alpha.get_router().disable_interface()
        await client_alpha.get_router().enable_interface()
    else:
        notifications_before = connected_before = 0
        await client_alpha.restart_interface()

    async def check_logs(msg, count):
        await client_alpha.log.wait_for(msg, count=count, not_greater=NOT_GREATER)

    await check_logs(
        PLATFORM_AGNOSTIC_MESSAGE, notifications_before + NR_OF_NOTIFICATIONS
    )

    if target_os == TargetOS.Windows:
        # Interface is up again: Connected=true for IPv4 and IPv6
        await check_logs(WIN_CONNECTED, connected_before + 2)

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
