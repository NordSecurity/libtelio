import asyncio
import pytest
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from telio_features import (
    TelioFeatures,
    Direct,
    Lana,
    Wireguard,
    PersistentKeepalive,
)
from typing import List, Tuple
from utils.batch_observer import BatchObserver, Direction, Histogram, ObservationTarget
from utils.connection_util import ConnectionTag, new_connection_raw
from utils.ping import Ping

ANY_PROVIDERS = ["local", "stun"]

DOCKER_CONE_GW_1_IP = "10.0.254.1"
DOCKER_CONE_GW_2_IP = "10.0.254.2"
DOCKER_CONE_GW_3_IP = "10.0.254.7"


def _generate_setup_parameter_pair(
    cfg: List[Tuple[ConnectionTag, List[str]]],
) -> List[SetupParameters]:
    return [
        SetupParameters(
            connection_tag=conn_tag,
            adapter_type=telio.AdapterType.BoringTun,
            features=TelioFeatures(
                direct=Direct(providers=endpoint_providers),
                lana=Lana(prod=False, event_path="/event.db"),
                wireguard=Wireguard(
                    persistent_keepalive=PersistentKeepalive(
                        proxying=17, direct=5
                    )
                ),
            ),
        )
        for conn_tag, endpoint_providers in cfg
    ]


CLIENTS = [
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
            (ConnectionTag.DOCKER_CONE_CLIENT_3, ["stun"]),
        ]),
        DOCKER_CONE_GW_1_IP,
        DOCKER_CONE_GW_2_IP,
        DOCKER_CONE_GW_3_IP,
    ),
]


class Gateway:
    def __init__(self, name: str, tag: ConnectionTag, ip: str):
        self._name = name
        self._tag = tag
        self._ip = ip
        self._conn = None

    def __repr__(self):
        return f"Gateway({self._name}, {self._tag}, {self._ip}, {self._conn})"


@pytest.mark.asyncio
async def test_histogram():
    bo = Histogram(10)
    for _ in range(10):
        bo.add_value(2)
        bo.add_value(3)

    for _ in range(50):
        bo.add_value(4)

    bo.add_value(9)

    assert bo.bins() == [0, 0, 10, 10, 50, 0, 0, 0, 0, 1]


@pytest.mark.asyncio
async def test_histogram_3s():
    bo = BatchObserver("histogram_ping_3sec", None)
    hs_inc = bo.get_histogram(
        10, ObservationTarget(Direction.Incoming, "10.0.0.1")
    ).bins()
    hs_out = bo.get_histogram(
        10, ObservationTarget(Direction.Outgoing, "10.0.0.1")
    ).bins()
    hs_all = bo.get_histogram(10, ObservationTarget(Direction.Both, "10.0.0.1")).bins()

    assert hs_inc.index(max(hs_inc)) == 3
    assert hs_out.index(max(hs_out)) == 3

    v0, v1 = sorted(hs_all)[-2:]
    assert hs_all.index(v0) + hs_all.index(v1) == 3


@pytest.mark.asyncio
async def test_histogram_5s():
    bo = BatchObserver("histogram_ping_5sec", None)
    hs_inc = bo.get_histogram(
        10, ObservationTarget(Direction.Incoming, "10.0.0.2")
    ).bins()
    hs_out = bo.get_histogram(
        10, ObservationTarget(Direction.Outgoing, "10.0.0.2")
    ).bins()
    hs_all = bo.get_histogram(10, ObservationTarget(Direction.Both, "10.0.0.2")).bins()

    assert hs_inc.index(max(hs_inc)) == 5
    assert hs_out.index(max(hs_out)) == 5

    v0, v1 = sorted(hs_all)[-2:]
    assert hs_all.index(v0) + hs_all.index(v1) == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, alpha_ip, beta_ip, gamma_ip", CLIENTS)
async def test_direct_batching(
    setup_params: List[SetupParameters], alpha_ip: str, beta_ip: str, gamma_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        capture_nodes = [
            Gateway(
                "DOCKER_CONE_CLIENT_1",
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                "192.168.101.104",
            ),
            Gateway(
                "DOCKER_CONE_CLIENT_2",
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                "192.168.102.54",
            ),
            Gateway(
                "DOCKER_CONE_CLIENT_3",
                ConnectionTag.DOCKER_CONE_CLIENT_3,
                "192.168.102.55",
            ),
        ]

        asyncio.Event()

        async def run_batch_observer(gw: Gateway):
            print(f"Running batch observer for gateway: {gw._name}")

            async def print_histogram(
                conn_tag: ConnectionTag, name: str, obs_trg: ObservationTarget
            ):
                connection = await exit_stack.enter_async_context(
                    new_connection_raw(conn_tag)
                )
                bo = BatchObserver(f"{name}", connection)
                outgoing_bins = bo.get_histogram(30, obs_trg).bins()
                print(outgoing_bins)

            async with BatchObserver(f"{gw._name}", gw._conn).run() as bo:
                await asyncio.sleep(60 * 5)

                hs_inc = bo.get_histogram(
                    20, ObservationTarget(Direction.Incoming, gw._ip)
                ).bins()
                hs_out = bo.get_histogram(
                    20, ObservationTarget(Direction.Outgoing, gw._ip)
                ).bins()
                print_histogram(hs_inc)
                print_histogram(hs_out)

        tasks = []
        for gw in capture_nodes:
            connection = await exit_stack.enter_async_context(
                new_connection_raw(gw._tag)
            )
            gw._conn = connection
            task = asyncio.create_task(run_batch_observer(gw))
            tasks.append(task)

        # The IPs here are in-meshnet IPs
        env = await setup_mesh_nodes(exit_stack, setup_params)
        _alpha, beta, gamma = env.nodes
        _, beta_client, _ = env.clients
        alpha_connection, beta_connection, gamma_connection = [
            conn.connection for conn in env.connections
        ]

        async def run_ping(dest_ip: str):
            async with Ping(alpha_connection, dest_ip, True).run() as ping:
                await ping.wait_for_next_ping(15)

        async def misalign():
            await asyncio.sleep(10)
            async with beta_client.get_router().break_udp_conn_to_host(alpha_ip):
                await asyncio.sleep(25)
                await run_ping(beta.ip_addresses[0])

        await asyncio.gather(
            misalign(),
            run_ping(beta.ip_addresses[0]),
            run_ping(gamma.ip_addresses[0]),
            run_ping("10.0.10.1"),
            *tasks,
        )
