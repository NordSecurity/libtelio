import time

import Pyro5.api  # type: ignore
from Pyro5.api import Proxy  # type: ignore


def handle_error(f):
    def wrap(*args, **kwargs):
        fn_res = f(*args, **kwargs)
        if fn_res == None:
            return None
        (res, err) = fn_res
        if err != None:
            raise Exception(err)
        return res

    return wrap


class LibtelioProxy(object):
    def __init__(self, object_uri: str, features: str):
        self._uri = object_uri
        iterations = 20
        for i in range(0, iterations):
            try:
                self._create(features)
                return
            except Exception as err:
                if i == iterations - 1:
                    raise Exception(f"Couldn't connect to remote uri due to: {err}")
                else:
                    time.sleep(0.25)

    @handle_error
    def _create(self, features: str):
        with Proxy(self._uri) as remote:
            remote.create(features)

    @handle_error
    def next_event(self):
        with Proxy(self._uri) as remote:
            return remote.next_event()

    @handle_error
    def stop(self):
        with Proxy(self._uri) as remote:
            remote.stop()

    @handle_error
    def start_named(self, private_key, adapter, name: str):
        with Proxy(self._uri) as remote:
            remote.start_named(private_key, adapter.value, name)

    @handle_error
    def set_fwmark(self, fwmark: int):
        with Proxy(self._uri) as remote:
            remote.set_fwmark(fwmark)

    @handle_error
    def notify_network_change(self):
        with Proxy(self._uri) as remote:
            remote.notify_network_change()

    @handle_error
    def connect_to_exit_node(self, public_key, allowed_ips: str, endpoint: str):
        with Proxy(self._uri) as remote:
            remote.connect_to_exit_node(public_key, allowed_ips, endpoint)

    @handle_error
    def disconnect_from_exit_nodes(self):
        with Proxy(self._uri) as remote:
            remote.disconnect_from_exit_nodes()

    @handle_error
    def enable_magic_dns(self, forward_servers: str):
        with Proxy(self._uri) as remote:
            remote.enable_magic_dns(forward_servers)

    @handle_error
    def disable_magic_dns(self):
        with Proxy(self._uri) as remote:
            remote.disable_magic_dns()

    @handle_error
    def set_meshnet(self, cfg: str):
        with Proxy(self._uri) as remote:
            remote.set_meshnet(cfg)

    @handle_error
    def set_meshnet_off(self):
        with Proxy(self._uri) as remote:
            remote.set_meshnet_off()

    @handle_error
    def is_running(self) -> bool:
        with Proxy(self._uri) as remote:
            return remote.is_running()

    @handle_error
    def trigger_analytics_event(self) -> None:
        with Proxy(self._uri) as remote:
            remote.trigger_analytics_event()
