import time
from Pyro5.api import Proxy  # type: ignore


class LibtelioProxy:
    def __init__(self, object_uri: str, features: str):
        self._uri = object_uri
        iterations = 20
        for i in range(0, iterations):
            try:
                self._create(features)
                return
            except Exception as err:
                if i == iterations - 1:
                    raise Exception(f"Couldn't connect to remote uri due to: {err}") from err
                time.sleep(0.25)

    def handle_remote_error(self, f):
        with Proxy(self._uri) as remote:
            fn_res = f(remote)
            if fn_res is None:
                return None
            (res, err) = fn_res
            if err is not None:
                raise Exception(err)
            return res

    def _create(self, features: str):
        self.handle_remote_error(lambda r: r.create(features))

    def next_event(self):
        self.handle_remote_error(lambda r: r.next_event())

    def stop(self):
        self.handle_remote_error(lambda r: r.stop())

    def start_named(self, private_key, adapter, name: str):
        self.handle_remote_error(lambda r: r.start_named(private_key, adapter.value, name))

    def set_fwmark(self, fwmark: int):
        self.handle_remote_error(lambda r: r.set_fwmark(fwmark))

    def notify_network_change(self):
        self.handle_remote_error(lambda r: r.notify_network_change())

    def connect_to_exit_node(self, public_key, allowed_ips, endpoint):
        self.handle_remote_error(lambda r: r.connect_to_exit_node(public_key, allowed_ips, endpoint))

    def disconnect_from_exit_nodes(self):
        self.handle_remote_error(lambda r: r.disconnect_from_exit_nodes())

    def enable_magic_dns(self, forward_servers):
        self.handle_remote_error(lambda r: r.enable_magic_dns(forward_servers))

    def disable_magic_dns(self):
        self.handle_remote_error(lambda r: r.disable_magic_dns())

    def set_meshnet(self, cfg: str):
        self.handle_remote_error(lambda r: r.set_meshnet(cfg))

    def set_meshnet_off(self):
        self.handle_remote_error(lambda r: r.set_meshnet_off())

    def is_running(self) -> bool:
        return self.handle_remote_error(lambda r: r.is_running())

    def trigger_analytics_event(self) -> None:
        self.handle_remote_error(lambda r: r.trigger_analytics_event())
