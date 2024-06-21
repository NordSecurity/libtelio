import asyncio
import re
from contextlib import asynccontextmanager
from ipaddress import ip_address
import subprocess
import time
from typing import AsyncIterator
import typing
from utils import testing
from utils.connection import Connection, TargetOS
from utils.process import Process
from utils.router import IPProto, REG_IPV6ADDR, get_ip_address_type
import scapy.all as scapy


class Histogram:
    def __init__(self, bins: int, range: typing.Tuple[float, float]) -> None:
        self._bins = bins
        self._start = range[0]
        self._end = range[1]
        self._histogram = [0] * bins
        self._bin_width = (self._end - self._start) / bins
        
    def add_value(self, value: float) -> None:
        if value < self._start or value > self._end:
            raise ValueError(f"Value {value} is out of range")

        bin_index = int((value - self._start) / self._bin_width)
        self._histogram[bin_index] += 1

    def bins(self) -> typing.List[int]:
        return self._histogram
    
    def __repr__(self) -> str:
        return f"Histogram(bins={self._histogram})"
    
class EventCollection:
    def __init__(self) -> None:
        self._events: typing.List[Event] = []
        
    
    def add_event(self, event: "Event") -> None:
        self._events.append(event)
    
    def get_histogram(self, hs_buckets, hs_range: typing.Tuple[int,int]) -> Histogram:
        histogram = Histogram(hs_buckets, hs_range)        
        for event in self._events:
            histogram.add_value(event._timestamp)
        return histogram
        
    
# tcpdump ioutgoing event
class Event:
    _timestamp: float
    _src_ip: str
    _dst_ip: str

    def __init__(self, timestamp: float, src_ip: str, dst_ip: str) -> None:
        self._timestamp = timestamp
        self._src_ip = src_ip
        self._dst_ip = dst_ip

    def __repr__(self) -> str:
        return (
            f"Event(timestamp={self._timestamp}, src_ip={self._src_ip},"
            f" dst_ip={self._dst_ip})"
        )



class Direction:
    Both = 0
    Incoming = 1
    Outgoing = 2
        
# BatchObserver launches tcpdump inside of the container and captures all of the traffic
class BatchObserver:
    def __init__(
        self,
        name: str,
        connection: Connection,        
        ip: str,
    ) -> None:
        self._events: typing.List[Event] = []
        self._name = name
        self._connection = connection        
        self._ip = ip
                
    async def on_stdout(self, line: str) -> None:
        print(f"!!!!!!!!!!!!!!! stdout: {line}", flush=True)

    async def on_stderr(self, line: str) -> None:
        print(f"!!!!!!!!!!!!!!! stderr: {line}", flush=True)

    async def execute(self) -> None:
        try:
            async with self._process.run(
                stdout_callback=self.on_stdout, stderr_callback=self.on_stderr
            ):
                await asyncio.sleep(self._duration_s)
        except asyncio.CancelledError as e:
            pass
        finally:
            pass

    async def on_stdout(self, stdout: str) -> None:
        print(f"!!!!!!!!!!!!!!! stdout: {stdout}", flush=True)
        
    @asynccontextmanager
    async def run(self) -> AsyncIterator["BatchObserver"]:
        if self._connection is None:
            raise ValueError("Connection is not set. This BatchObserver is read-only")
        
        print(")))))))))))))))))))))))))))))0")
        interface = "eth0"
        self._process = self._connection.create_process(            
            [
                "tcpdump",
                "-l",
                "-n",
                "-i",
                f"{interface}",
                "-w",
                f"/libtelio/{self._name}.pcap",
                "-Z",
                "root",
            ]
        )
        
        async with self._process.run(stdout_callback=self.on_stdout, stderr_callback=self.on_stderr):
            print("))))))))))))))) run", time.time())
            yield self

    def get_histogram(self, hs_buckets: int, hs_range: typing.Tuple[int,int], direction: Direction = Direction.Both) -> EventCollection:
        assert hs_buckets > 0
        assert hs_range[0] < hs_range[1]
        
        filepath = f"./{self._name}.pcap"
        
        evc = EventCollection()
        with scapy.PcapReader(filepath) as pcap_reader:
            last_pkt_time = None
            last_pkt = None
            
            for pkt in pcap_reader:                
                if not pkt.haslayer(scapy.IP):
                    continue
            
                # filter out management traffic. Pyro5 is being used for that
                if pkt.haslayer(scapy.TCP):
                    if pkt[scapy.TCP].dport >= 30000 and pkt[scapy.TCP].dport <= 30300:
                        continue
                    if pkt[scapy.TCP].sport >= 30000 and pkt[scapy.TCP].sport <= 30300:
                        continue
                    
                if pkt.haslayer(scapy.UDP):
                    if pkt[scapy.UDP].dport >= 22222 and pkt[scapy.UDP].dport <= 33333:
                        continue
                    if pkt[scapy.UDP].sport >= 22222 and pkt[scapy.UDP].sport <= 33333:
                        continue
                
                # ignore derp servers for a while. Can't ignore them really as they make
                # the whole traffic when relayed
                # if pkt.haslayer(scapy.TCP):
                #     if pkt[scapy.TCP].dport == 8765:
                #         continue
                #     if pkt[scapy.TCP].sport == 8765:
                #         continue
            
                src = pkt[scapy.IP].src
                dst = pkt[scapy.IP].dst

                # # TODO: do not know exactly what that means but I can see a lot of pinging between these two
                # if src == "10.0.0.1" or dst == "10.0.0.1":
                #     continue
                
                # if src == "10.0.0.2" or dst == "10.0.0.2":
                #     continue
                
                # print(pkt.summary())
                # filter packets based on direction
                
                if direction == Direction.Incoming:
                    if dst != self._ip:
                        continue
                elif direction == Direction.Outgoing:
                    if src != self._ip:
                        continue
                else:
                    if src != self._ip and dst != self._ip:
                        continue
                
                if last_pkt_time is None:
                    last_pkt_time = pkt.time
                else:
                    last_pkt_time = last_pkt.time
                last_pkt = pkt
            
                tdelta = pkt.time - last_pkt_time
                print(direction, f"tdelta: {tdelta}", pkt.summary(), pkt.time, pkt.time)
                    
                assert tdelta >= 0 
                evc.add_event(Event(tdelta, src, dst))
        return evc.get_histogram(hs_buckets, hs_range)

    