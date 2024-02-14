import base64
import datetime
import os
import Pyro5.api  # type: ignore
import Pyro5.server  # type: ignore
import sys
import telio_bindings as libtelio  # type: ignore # pylint: disable=import-error
from typing import List

REMOTE_LOG = "remote.log"
TCLI_LOG = "tcli.log"


def serialize_error(f):
    def wrap(*args, **kwargs):
        with open(REMOTE_LOG, "a", encoding="utf-8") as logfile:
            fname = str(f).split(" ")[1]
            args_str = ", ".join(map(str, args[1:]))
            try:
                res = f(*args, **kwargs)
                logfile.write(
                    f"{datetime.datetime.now()} {fname}({args_str}) => {res}\n"
                )
                return (res, None)
            except libtelio.TelioError as e:
                logfile.write(
                    f"{datetime.datetime.now()} {fname}({args_str}) => {str(e)}\n"
                )
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
    def log(self, log_level, payload):
        with open(TCLI_LOG, "a", encoding="utf-8") as logfile:
            try:
                logfile.write(f"{datetime.datetime.now()} {log_level} {payload}\n")
            except IOError as e:
                logfile.write(
                    f"{datetime.datetime.now()} Failed to write logline due to error {str(e)}\n"
                )


@Pyro5.api.expose
@Pyro5.server.behavior(instance_mode="single")
class LibtelioWrapper:
    def __init__(self, daemon):
        try:
            os.remove(REMOTE_LOG)
        except:
            pass

        self._daemon = daemon

        self._libtelio = None
        self._event_cb = TelioEventCbImpl()
        self._logger_cb = TelioLoggerCbImpl()
        libtelio.set_global_logger(libtelio.TelioLogLevel.DEBUG, self._logger_cb)

    def shutdown(self):
        self._daemon.shutdown()

    @serialize_error
    def create(self, features: str):
        features = libtelio.deserialize_feature_config(features)
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
    def connect_to_exit_node_pq(self, public_key, allowed_ips: str, endpoint: str):
        self._libtelio.connect_to_exit_node_postquantum(
            "natlabpq", base64.b64decode(public_key), allowed_ips, endpoint
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
        cfg = libtelio.deserialize_meshnet_config(cfg)
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

    @serialize_error
    def trigger_qos_collection(self) -> None:
        self._libtelio.trigger_qos_collection()


def main():
    object_name = sys.argv[1]
    container_ip = sys.argv[2]
    port = int(sys.argv[3])

    daemon = Pyro5.server.Daemon(host=container_ip, port=port)
    wrapper = LibtelioWrapper(daemon)
    daemon.register(wrapper, objectId=object_name)

    daemon.requestLoop()
    daemon.close()


if __name__ == "__main__":
    main()
