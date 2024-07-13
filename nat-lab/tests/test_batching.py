# Batching works by checking if certain packets can be sent together. This means that
# in order to test it's effects we can filter outgoing data and then check the time deltas.
# When batching is in action time deltas should fall into the left side of the histogram because
# deltas should be very small as packets leave in succession. There should be no action in
# the middle and then histogram should have data on the interval boundary. Basically letter "U" shaped.
# When using no batching, histogram might look very differently depending on the signal misalignment. Testing
# depends highly on misalignment and must be taken into an account.

import asyncio
import os
import pytest
import subprocess
import telio
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from mesh_api import Node
from telio import State, PathType
from telio_features import TelioFeatures, Direct, Wireguard, PersistentKeepalive
from typing import Any, List, Tuple
from utils.batch_observer import (
    BatchObserver,
    Direction,
    Histogram,
    ObservationTarget,
    TargetMachine,
)
from utils.connection_util import ConnectionTag
from utils.router import IPStack


class HistogramResult:
    def __init__(self, incoming: List, outgoing: List):
        self.incoming = incoming
        self.outgoing = outgoing

    def __repr__(self):
        return f"HistogramResult(outgoing={self.outgoing}, incoming={self.incoming})"


class BatchTestFeatures:
    def __init__(
        self,
        direct_interval: int,
        direct_threshold: int,
        is_meshnet: bool,
        ip_stack: IPStack,
    ):
        self.direct_interval = direct_interval
        self.direct_threshold = direct_threshold
        self.is_meshnet = is_meshnet
        self.ip_stack: IPStack = ip_stack


def _generate_setup_parameters(
    cfg: List[Tuple[ConnectionTag, List[str], BatchTestFeatures, Any]],
) -> List[Tuple[SetupParameters, Any]]:
    return [
        (
            SetupParameters(
                is_meshnet=batching.is_meshnet,
                ip_stack=batching.ip_stack,
                connection_tag=conn_tag,
                adapter_type=telio.AdapterType.BoringTun,
                features=TelioFeatures(
                    direct=Direct(providers=endpoint_providers),
                    wireguard=Wireguard(
                        persistent_keepalive=PersistentKeepalive(
                            direct=batching.direct_interval,
                            direct_batching_threshold=batching.direct_threshold,
                        )
                    ),
                ),
            ),
            histogram_check_fn,
        )
        for conn_tag, endpoint_providers, batching, histogram_check_fn in cfg
    ]


def NO_BATCH_DOCKER_CONE_CLIENT_1_histogram_check(hs: HistogramResult):
    # should have no naturally aligned keepalives due to sleep
    assert hs.outgoing[8] == 0


def NO_BATCH_DOCKER_CONE_CLIENT_2_histogram_check(hs: HistogramResult):
    # should have no naturally aligned keepalives due to sleep
    assert hs.outgoing[8] == 0


def NO_BATCH_DOCKER_SHARED_CLIENT_1_histogram_check(_: HistogramResult):
    # TODO: I don't know how to test this propery.
    # The histogram looks as such:
    # hs = HistogramResult(outgoing=[1, 0, 0, 4, 5, 0, 0, 0, 0, 0], incoming=[1, 0, 0, 4, 5, 0, 0, 0, 0, 0])
    # SessionKeeper is called with a 2 second delay for alpha and beta for adding gamma peer, meaning this is
    # at least the current behaviour, I would expect it to be immediate and have no idea
    # where the 2 seconds come from.
    pass


CLIENTS_NO_BATCHING = [
    pytest.param(
        _generate_setup_parameters([
            (
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ["stun", "local", "upnp"],
                BatchTestFeatures(
                    direct_interval=4,
                    direct_threshold=0,
                    is_meshnet=True,
                    ip_stack=IPStack.IPv4,
                ),
                NO_BATCH_DOCKER_CONE_CLIENT_1_histogram_check,
            ),
            (
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                ["stun", "local", "upnp"],
                BatchTestFeatures(
                    direct_interval=4,
                    direct_threshold=0,
                    is_meshnet=True,
                    ip_stack=IPStack.IPv4,
                ),
                NO_BATCH_DOCKER_CONE_CLIENT_2_histogram_check,
            ),
            (
                ConnectionTag.DOCKER_SHARED_CLIENT_1,
                ["stun", "local", "upnp"],
                BatchTestFeatures(
                    direct_interval=4,
                    direct_threshold=0,
                    is_meshnet=False,
                    ip_stack=IPStack.IPv4,
                ),
                NO_BATCH_DOCKER_SHARED_CLIENT_1_histogram_check,
            ),
        ])
    ),
]


def BATCHED_DOCKER_CONE_CLIENT_1_histogram_check(hs: HistogramResult):
    assert hs.outgoing[0] == 6
    assert sum(hs.outgoing[7:8]) == 4
    assert sum(hs.outgoing[1:7]) == 0


def BATCHED_DOCKER_CONE_CLIENT_2_histogram_check(hs: HistogramResult):
    assert hs.outgoing[0] == 6
    assert sum(hs.outgoing[8:9]) == 4
    assert sum(hs.outgoing[1:7]) == 0


def BATCHED_DOCKER_SHARED_CLIENT_1_histogram_check(hs: HistogramResult):
    assert hs.outgoing[0] == 6
    assert sum(hs.outgoing[8:9]) == 4
    assert sum(hs.outgoing[1:7]) == 0


CLIENTS_BATCHING = [
    pytest.param(
        _generate_setup_parameters([
            (
                ConnectionTag.DOCKER_CONE_CLIENT_1,
                ["stun", "local", "upnp"],
                BatchTestFeatures(
                    direct_interval=4,
                    direct_threshold=2,
                    is_meshnet=True,
                    ip_stack=IPStack.IPv4,
                ),
                BATCHED_DOCKER_CONE_CLIENT_1_histogram_check,
            ),
            (
                ConnectionTag.DOCKER_CONE_CLIENT_2,
                ["stun", "local", "upnp"],
                BatchTestFeatures(
                    direct_interval=4,
                    direct_threshold=2,
                    is_meshnet=True,
                    ip_stack=IPStack.IPv4,
                ),
                BATCHED_DOCKER_CONE_CLIENT_2_histogram_check,
            ),
            (
                ConnectionTag.DOCKER_SHARED_CLIENT_1,
                ["stun", "local", "upnp"],
                BatchTestFeatures(
                    direct_interval=4,
                    direct_threshold=2,
                    is_meshnet=False,
                    ip_stack=IPStack.IPv4,
                ),
                BATCHED_DOCKER_SHARED_CLIENT_1_histogram_check,
            ),
        ])
    ),
]


async def get_batch_histogram(
    target: TargetMachine, mesh_node: Node
) -> HistogramResult:
    print(f"Running batch observer for target: {target.tag}")

    await asyncio.sleep(2)
    async with BatchObserver(target).run() as bo:
        await asyncio.sleep(20)

        local_path = f"./{target.tag}.pcap"
        remote_path = local_path

        subprocess.run([
            "docker",
            "cp",
            target.container_id + ":" + remote_path,
            local_path,
        ])

        # talking in milliseconds
        hs_in = bo.get_histogram(
            10,
            500,
            ObservationTarget(Direction.Incoming, mesh_node.ip_addresses[0]),
        )
        hs_out = bo.get_histogram(
            10,
            500,
            ObservationTarget(Direction.Outgoing, mesh_node.ip_addresses[0]),
        )
        os.unlink(local_path)

        return HistogramResult(hs_in, hs_out)


@pytest.mark.asyncio
async def test_histogram():
    bo = Histogram()
    for _ in range(10):
        bo.add_value(2)
        bo.add_value(3)

    for _ in range(50):
        bo.add_value(4)

    bo.add_value(9)

    assert bo.get(10, 1) == [0, 0, 10, 10, 50, 0, 0, 0, 0, 1]


# nodes that will capture the traffic
capture_nodes: List[ConnectionTag] = [
    ConnectionTag.DOCKER_CONE_CLIENT_1,
    ConnectionTag.DOCKER_CONE_CLIENT_2,
    ConnectionTag.DOCKER_SHARED_CLIENT_1,
]


@pytest.mark.asyncio
@pytest.mark.parametrize("client_params", [CLIENTS_NO_BATCHING, CLIENTS_BATCHING])
async def test_direct_batching(client_params: Any) -> None:
    async with AsyncExitStack() as exit_stack:
        for setup_params in client_params:
            # This testcase initiates 2 meshnet peers, and after a small delay initiates the third peer.
            # The reason for this is to misalign their keepalive echo requests and observe batching in action
            # The third peer has naturally aligned keepalives even if with no batching as it received meshmap
            # with both peers at once and added the keys

            setup_params = setup_params[0][0]  # TODO: Pytest, wtf

            mesh_params = [p for p, _ in setup_params]
            env = await setup_mesh_nodes(exit_stack, mesh_params)
            alpha, beta, gamma = env.nodes
            _, _, gamma_client = env.clients

            await asyncio.sleep(2)

            await gamma_client.set_meshmap(env.api.get_meshmap(gamma.id))
            await gamma_client.wait_for_state_peer(
                alpha.public_key, [State.Connected], [PathType.Direct]
            )
            await gamma_client.wait_for_state_peer(
                beta.public_key, [State.Connected], [PathType.Direct]
            )

            tasks = []
            node_index = 0
            nodes = [alpha, beta, gamma]
            for tag in capture_nodes:
                node = nodes[node_index]
                task: Any = asyncio.create_task(
                    get_batch_histogram(TargetMachine(tag), node)
                )
                tasks.append((tag, task))
                node_index += 1

            results = await asyncio.gather(*(task for _, task in tasks))
            tag_to_result = {tag: result for (tag, _), result in zip(tasks, results)}

            validators = [p for _, p in setup_params]
            validator_index = 0
            for tag, hs in tag_to_result.items():
                validator = validators[validator_index]
                validator(hs)
                validator_index += 1
