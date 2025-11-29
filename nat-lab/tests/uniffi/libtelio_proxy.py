import asyncio
import os
import Pyro5.errors  # type:ignore
import sys
import tests.uniffi.telio_bindings as libtelio
import time
from functools import wraps
from Pyro5.api import Proxy  # type: ignore
from tests.uniffi.serialization import init_serialization  # type: ignore
from typing import List, Optional

# isort: off
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tests.utils.logger import log  # type: ignore # pylint: disable=wrong-import-position

# isort: on

# This call will allow the proxy-side of the Pyro5 connection to handle types defined in libtelio.udl
init_serialization(libtelio)


class ProxyConnectionError(Exception):
    def __init__(self, inner):
        self._inner = inner

    def __str__(self):
        return f"ProxyConnectionError: {self._inner}"


def move_to_async_thread(f):
    @wraps(f)
    async def wrap(*args, **kwargs):
        return await asyncio.to_thread(f, *args, **kwargs)

    return wrap


class LibtelioProxy:
    def __init__(self, object_uri: str, features: libtelio.Features):
        self._uri = object_uri
        self._iterations = 20
        self._features = features

    def _handle_remote_error(self, f):
        with Proxy(self._uri) as remote:
            fn_res = f(remote)
            if fn_res is None:
                return None
            (res, err) = fn_res
            if err is not None:
                raise Exception(err)
            return res

    @move_to_async_thread
    def shutdown(self, container_or_vm_name: Optional[str] = None):
        try:
            with Proxy(self._uri) as remote:
                remote.shutdown()
            log.info(
                "Libtelio Proxy connection has been successfully shut down on %s",
                "Unknown" if container_or_vm_name is None else container_or_vm_name,
            )

        except (
            Pyro5.errors.ConnectionClosedError,
            ConnectionRefusedError,
            Pyro5.errors.CommunicationError,
        ) as e:
            # Shutting down the server via client request is naturally racy,
            # as sending of response is racing against process shutdown (and
            # thus server-side socket being closed).
            # In general handling process lifetime via client-side RPC Communication
            # is not the best idea, therefore to fix that LLT-5223 was created. But
            # there is a need to verify whether this specific race is in-fact actual
            # cause of the flakyness. Therefore the exception for ConnectionClosedError
            # is added
            log.warning(
                "ConnectionClosedError raised during shutdown of libtelio RPC daemon on %s exception: %s",
                "Unknown" if container_or_vm_name is None else container_or_vm_name,
                e,
            )

    @move_to_async_thread
    def create(self):
        for i in range(0, self._iterations):
            try:
                self._handle_remote_error(lambda r: r.create(self._features))
                return
            except Pyro5.errors.CommunicationError as err:
                if i == self._iterations - 1:
                    raise ProxyConnectionError(err) from err
                time.sleep(0.25)

    @move_to_async_thread
    def next_event(self) -> libtelio.Event:
        return self._handle_remote_error(lambda r: r.next_event())

    @move_to_async_thread
    def stop(self):
        self._handle_remote_error(lambda r: r.stop())

    @move_to_async_thread
    def start_named(self, private_key, adapter, name: str):
        self._handle_remote_error(
            lambda r: r.start_named(private_key, adapter.value, name)
        )

    @move_to_async_thread
    def create_tun(self, tun_name: str) -> int:
        return self._handle_remote_error(lambda r: r.create_tun(tun_name))

    @move_to_async_thread
    def start_with_tun(self, private_key, adapter, tun: int):
        self._handle_remote_error(
            lambda r: r.start_with_tun(private_key, adapter.value, tun)
        )

    @move_to_async_thread
    def start_named_ext_if_filter(
        self, private_key, adapter, name: str, ext_if_list: List[str]
    ):
        self._handle_remote_error(
            lambda r: r.start_named_ext_if_filter(
                private_key, adapter.value, name, ext_if_list
            )
        )

    @move_to_async_thread
    def set_fwmark(self, fwmark: int):
        self._handle_remote_error(lambda r: r.set_fwmark(fwmark))

    @move_to_async_thread
    def set_ext_if_filter(self, ext_if_list: List[str]):
        self._handle_remote_error(lambda r: r.set_ext_if_filter(ext_if_list))

    @move_to_async_thread
    def set_tun(self, tun: int):
        self._handle_remote_error(lambda r: r.set_tun(tun))

    @move_to_async_thread
    def notify_network_change(self):
        self._handle_remote_error(lambda r: r.notify_network_change())

    @move_to_async_thread
    def connect_to_exit_node(self, public_key, allowed_ips, endpoint):
        self._handle_remote_error(
            lambda r: r.connect_to_exit_node(public_key, allowed_ips, endpoint)
        )

    @move_to_async_thread
    def connect_to_exit_node_pq(self, public_key, allowed_ips, endpoint):
        self._handle_remote_error(
            lambda r: r.connect_to_exit_node_pq(public_key, allowed_ips, endpoint)
        )

    @move_to_async_thread
    def disconnect_from_exit_nodes(self):
        self._handle_remote_error(lambda r: r.disconnect_from_exit_nodes())

    @move_to_async_thread
    def enable_magic_dns(self, forward_servers):
        self._handle_remote_error(lambda r: r.enable_magic_dns(forward_servers))

    @move_to_async_thread
    def disable_magic_dns(self):
        self._handle_remote_error(lambda r: r.disable_magic_dns())

    @move_to_async_thread
    def set_meshnet(self, cfg: libtelio.Config):
        self._handle_remote_error(lambda r: r.set_meshnet(cfg))

    @move_to_async_thread
    def set_meshnet_off(self):
        self._handle_remote_error(lambda r: r.set_meshnet_off())

    @move_to_async_thread
    def set_secret_key(self, secret_key):
        self._handle_remote_error(lambda r: r.set_secret_key(secret_key))

    @move_to_async_thread
    def is_running(self) -> bool:
        return self._handle_remote_error(lambda r: r.is_running())

    @move_to_async_thread
    def trigger_analytics_event(self) -> None:
        self._handle_remote_error(lambda r: r.trigger_analytics_event())

    @move_to_async_thread
    def trigger_qos_collection(self) -> None:
        self._handle_remote_error(lambda r: r.trigger_qos_collection())

    @move_to_async_thread
    def receive_ping(self) -> str:
        return self._handle_remote_error(lambda r: r.receive_ping())

    @move_to_async_thread
    def flush_logs(self) -> None:
        self._handle_remote_error(lambda r: r.flush_logs())
