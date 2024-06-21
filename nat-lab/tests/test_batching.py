import asyncio
import base64
import time
import config
import pytest
import re
import telio
from config import DERP_SERVERS
from contextlib import AsyncExitStack
from helpers import setup_mesh_nodes, SetupParameters
from itertools import groupby
from telio import PathType, State
from telio_features import (
    TelioFeatures,
    Direct,
    Lana,
    Nurse,
    Wireguard,
    SkipUnresponsivePeers,
    FeatureEndpointProvidersOptimization,
    PersistentKeepalive,
)
from typing import List, Tuple
from utils import testing
from utils.asyncio_util import run_async_context
from utils.connection_util import ConnectionTag, DOCKER_GW_MAP, new_connection_raw
from utils.ping import Ping
from utils.batch_observer import BatchObserver, Direction, Histogram

ANY_PROVIDERS = ["local", "stun"]

DOCKER_CONE_GW_1_IP = "10.0.254.1"
DOCKER_CONE_GW_2_IP = "10.0.254.2"
DOCKER_OPEN_INTERNET_CLIENT_1_IP = "10.0.11.2"
DOCKER_OPEN_INTERNET_CLIENT_2_IP = "10.0.11.+"
DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK_IP = "10.0.11.4"
DOCKER_SYMMETRIC_CLIENT_1_IP = "192.168.103.88"
DOCKER_INTERNAL_SYMMETRIC_CLIENT_1_IP = "192.168.114.88"
DOCKER_SYMMETRIC_GW_1_IP = "10.0.254.3"
DOCKER_UPNP_CLIENT_2_IP = "10.0.254.12"


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
                    persistent_keepalive=PersistentKeepalive(proxying=17, direct=3)
                )
            ),
        )
        for conn_tag, endpoint_providers in cfg
    ]


CLIENTS = [    
    pytest.param(
        _generate_setup_parameter_pair([
            (ConnectionTag.DOCKER_CONE_CLIENT_1, ["stun"]),
            (ConnectionTag.DOCKER_CONE_CLIENT_2, ["stun"]),
        ]),
        DOCKER_CONE_GW_1_IP,
        DOCKER_CONE_GW_2_IP,
        
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
            

import asyncio

# Explanation for the histogram test setup:
# The histogram data is derived from a prerecorded pcap file, which captures continuous pinging to localhost every 3 seconds.
# Since both the source and destination are local, responses are instantaneous. This results in two primary types of events:
# one with virtually no delay (0 seconds) as responses are immediate, and another reflecting the regular 3-second ping interval.
# The histogram of these events is expected to display a U-shaped distribution, with peaks at 0 seconds and 3 seconds, capturing
# the immediate responses and the regular pinging interval, respectively.

@pytest.mark.asyncio
async def test_histogram():
    bo = Histogram(10, (0, 10))
    for _ in range(10):
        bo.add_value(2)
        bo.add_value(3)
    
    for _ in range(50):
        bo.add_value(4)
        
    bo.add_value(9)
    
    assert bo.bins() == [0, 0, 10, 10, 50, 0, 0, 0, 0, 1]
        

@pytest.mark.asyncio
async def test_histogram_3s():
    bo = BatchObserver("histogram_ping_3sec", None, "10.0.0.1")
    hs_inc = bo.get_histogram(10, (0, 10), Direction.Incoming).bins()
    hs_out = bo.get_histogram(10, (0, 10), Direction.Outgoing).bins()
    hs_all = bo.get_histogram(10, (0, 10), Direction.Both).bins()
        
    assert hs_inc.index(max(hs_inc)) == 3
    assert hs_out.index(max(hs_out)) == 3
    
    v0, v1 = sorted(hs_all)[-2:]    
    assert hs_all.index(v0) + hs_all.index(v1) == 3

@pytest.mark.asyncio
async def test_histogram_5s():
    bo = BatchObserver("histogram_ping_5sec", None, "10.0.0.2")
    hs_inc = bo.get_histogram(10, (0, 10), Direction.Incoming).bins()
    hs_out = bo.get_histogram(10, (0, 10), Direction.Outgoing).bins()
    hs_all = bo.get_histogram(10, (0, 10), Direction.Both).bins()
    
    assert hs_inc.index(max(hs_inc)) == 5
    assert hs_out.index(max(hs_out)) == 5
    
    v0, v1 = sorted(hs_all)[-2:]    
    assert hs_all.index(v0) + hs_all.index(v1) == 5

@pytest.mark.asyncio
@pytest.mark.parametrize("setup_params, _alpha_ip, _beta_ip", CLIENTS)
async def test_direct_batching(
    setup_params: List[SetupParameters],
    _alpha_ip: str,
    _beta_ip: str
) -> None:
    async with AsyncExitStack() as exit_stack:
        # gateways = [            
        #     Gateway("DOCKER_CONE_GW_1", ConnectionTag.DOCKER_CONE_GW_1, DOCKER_CONE_GW_1_IP),
        #     Gateway("DOCKER_CONE_GW_2", ConnectionTag.DOCKER_CONE_GW_2, DOCKER_CONE_GW_2_IP),            
        # ]
        capture_nodes = [            
            # Gateway("DOCKER_FULLCONE_CLIENT_1", ConnectionTag.DOCKER_FULLCONE_CLIENT_1, "192.168.109.88"),
            Gateway("DOCKER_CONE_CLIENT_1", ConnectionTag.DOCKER_CONE_CLIENT_1, "192.168.101.104"),
            Gateway("DOCKER_CONE_CLIENT_2", ConnectionTag.DOCKER_CONE_CLIENT_2, "192.168.102.54"),            
        ]
        
        now = asyncio.Event()
        async def run_batch_observer(gw: Gateway):
            await asyncio.wait_for(now.wait(), 20)
            print(f"Running batch observer for gateway: {gw._name}")
            hs_inc = []
            hs_out = []
            hs_all = []
            
            # capturing on gateways is better howevr the topology is also more complex, for exmaple we can expect two clients being connected to
            # two gateways, this means complex filtering on both gateways
            # so capturing on the client itself is simpler, however comes at a cost
            # of unreliability - the gateway capturing the traffic guarantees that it was emitted
            # meanwhile capturing on the node itself might mistakenly capture the traffic going from one interface to another
            # or if the traffic is not actually leaving the device might be taken into an account
                        
            async with BatchObserver(f"{gw._name}", gw._conn, gw._ip).run() as bo:
                print(">>>>>>>>>>>>>>>>>>>>> ", gw._name, " >>>>>>>>>>>>>>>>>>>>>")
                await asyncio.sleep(60)
                
                print("vvvvvvv INCOMING vvvvvv")
                hs_inc = bo.get_histogram(20, (0, 20), Direction.Incoming).bins()
                print("vvvvvvv OUTGOING vvvvvv")
                hs_out = bo.get_histogram(20, (0, 20), Direction.Outgoing).bins()
                print("vvvvvv BOTH vvvvvv")
                hs_all = bo.get_histogram(20, (0, 20), Direction.Both).bins()
                
                print(f">>>>>>>>>>>>>>>>>>>>> {gw._name} >>>>>>>>>>>>>>>>>>>>>")
                print(f"hs_inc: {hs_inc}")
                print(f"hs_out: {hs_out}")
                print(f"hs_all: {hs_all}")
                print(f"<<<<<<<<<<<<<<<<<<<<< {gw._name} <<<<<<<<<<<<<<<<<<<<<")                                                            
        
        print(".............................................")            
        tasks = []
        for gw in capture_nodes:
            print("Launching batch observer for gateway: ", gw._name, "with tag: ", gw._tag, "and ip: ", gw._ip, "and conn: ", gw._conn)
            connection = await exit_stack.enter_async_context(new_connection_raw(gw._tag))
            gw._conn = connection
            task = asyncio.create_task(run_batch_observer(gw))
            print("Launched batch observer for gateway: ", gw._name, "with tag: ", gw._tag, "and ip: ", gw._ip, "and conn: ", gw._conn)
            tasks.append(task)
                                
        print("************** await setup")
        # The IPs here are in-meshnet IPs
        env = await setup_mesh_nodes(exit_stack, setup_params)
        alpha, beta = env.nodes 
        _, _ = env.clients
        alpha_connection, beta_connection = [conn.connection for conn in env.connections]
                
        print("************** await setup done")
        print(".............................................")        
        print(".............................................", flush=True)
        
        await asyncio.sleep(5)
        now.set()
        
        async def run_ping_alpha(sleep_s: int):
            await asyncio.sleep(sleep_s)
            async with Ping(alpha_connection, beta.ip_addresses[0], True).run() as ping:
            # async with Ping(alpha_connection, "1.1.1.1", True).run() as ping:
                # TODO: here is a race condition, given some sleep before this command, it somehow doesn't work anymore
                await ping.wait_for_next_ping(5)
                  
        await asyncio.gather(*tasks)