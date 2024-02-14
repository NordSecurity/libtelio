import sys
import json
import base64
import time
from typing import List

import Pyro5.api  # type: ignore
import Pyro5.server  # type: ignore

import libtelio  # type: ignore


def serialize_error(f):
    def wrap(*args, **kwargs):
        try:
            res = f(*args, **kwargs)
            return (res, None)
        except libtelio.TelioError as e:
            return (None, str(e))

    return wrap


class TelioEventCbImpl(libtelio.TelioEventCb):
    def __init__(self):
        self._events = []

    def event(self, payload):
        self._events.append(payload)

    def next_event(self):
        if len(self._events) > 0:
            return self._events.pop(0)
        return None


@Pyro5.api.expose
@Pyro5.server.behavior(instance_mode="single")
class LibtelioWrapper(object):
    def __init__(self):
        self._libtelio = None
        self._event_cb = TelioEventCbImpl()

    @serialize_error
    def create(self, features: str):
        features = libtelio.string_to_features(features)
        self._libtelio = libtelio.Telio(features, self._event_cb)

    @serialize_error
    def next_event(self):
        return self._event_cb.next_event()

    @serialize_error
    def stop(self):
        self._libtelio.stop()

    @serialize_error
    def start_named(self, private_key, adapter, name: str):
        self._libtelio.start_named(
            base64.b64decode(private_key), libtelio.TelioAdapterType(adapter), name
        )

    @serialize_error
    def set_fwmark(self, fwmark: int):
        self._libtelio.set_fwmark(fwmark)

    @serialize_error
    def notify_network_change(self):
        self._libtelio.notify_network_change("")

    @serialize_error
    def connect_to_exit_node(self, public_key, allowed_ips: str, endpoint: str):
        self._libtelio.connect_to_exit_node(
            base64.b64decode(public_key), allowed_ips, endpoint
        )

    @serialize_error
    def disconnect_from_exit_nodes(self):
        self._libtelio.disconnect_from_exit_nodes()

    @serialize_error
    def enable_magic_dns(self, forward_servers: List[str]):
        self._libtelio.enable_magic_dns(forward_servers)

    @serialize_error
    def disable_magic_dns(self):
        self._libtelio.disable_magic_dns()

    @serialize_error
    def set_meshnet(self, cfg: str):
        cfg = libtelio.string_to_meshnet_config(cfg)
        self._libtelio.set_meshnet(cfg)

    @serialize_error
    def set_meshnet_off(self):
        self._libtelio.set_meshnet_off()

    @serialize_error
    def is_running(self) -> bool:
        return self._libtelio.is_running()

    @serialize_error
    def trigger_analytics_event(self) -> None:
        self._libtelio.trigger_analytics_event()


def main(object_name, container_ip, port):
    daemon = Pyro5.server.Daemon(host=container_ip, port=port)
    uri = daemon.register(LibtelioWrapper, objectId=object_name)

    start_time = time.time()

    def daemon_should_be_alive():
        current_time = time.time()
        return (current_time - start_time) < 180

    daemon.requestLoop(daemon_should_be_alive)


if __name__ == "__main__":
    object_name = sys.argv[1]
    container_ip = sys.argv[2]
    port = int(sys.argv[3])
    main(object_name, container_ip, port)
