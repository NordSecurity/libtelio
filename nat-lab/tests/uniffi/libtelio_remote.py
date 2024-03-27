import base64
import libtelio  # type: ignore
import Pyro5.api  # type: ignore
import Pyro5.server  # type: ignore
import sys
import datetime
import time
from typing import List
import os


REMOTE_LOG = "remote.log"
TCLI_LOG = "tcli.log"


def serialize_error(f):
    def wrap(*args, **kwargs):
        with open(REMOTE_LOG, "a") as logfile:
            fname = str(f).split(" ")[1]
            args_str = ', '.join(map(str,args[1:]))
            try:
                res = f(*args, **kwargs)
                logfile.write(f"{datetime.datetime.now()} {fname}({args_str}) => {res}\n")
                return (res, None)
            except libtelio.TelioError as e:
                logfile.write(f"{datetime.datetime.now()} {fname}({args_str}) => {str(e)}\n")
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

    
class TelioLoggerCbImpl(libtelio.TelioLoggerCb):
    def __init__(self):
        self._log_file = open(TCLI_LOG, "a")
    
    def __del__(self):
        self._log_file.close()

    def log(self, log_level, payload):
        self._log_file.write(f"{datetime.datetime.now()} {log_level} {payload}\n")


@Pyro5.api.expose
@Pyro5.server.behavior(instance_mode="single")
class LibtelioWrapper:
    def __init__(self):
        try:
            os.remove(REMOTE_LOG)
        except:
            pass

        self._libtelio = None
        self._event_cb = TelioEventCbImpl()
        self._logger_cb = TelioLoggerCbImpl()
        libtelio.set_global_logger(libtelio.TelioLogLevel.DEBUG, self._logger_cb)

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
        self._libtelio.connect_to_exit_node_with_id(
            "natlab", base64.b64decode(public_key), allowed_ips, endpoint
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


def main():
    object_name = sys.argv[1]
    container_ip = sys.argv[2]
    port = int(sys.argv[3])

    daemon = Pyro5.server.Daemon(host=container_ip, port=port)
    daemon.register(LibtelioWrapper, objectId=object_name)

    start_time = time.time()

    def daemon_should_be_alive():
        current_time = time.time()
        return (current_time - start_time) < 180

    daemon.requestLoop(daemon_should_be_alive)


if __name__ == "__main__":
    main()
