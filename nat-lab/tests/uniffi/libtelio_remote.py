import datetime
import os
import Pyro5.api  # type: ignore
import Pyro5.server  # type: ignore
import shutil
import socket
import struct
import sys
import telio_bindings as libtelio  # type: ignore # pylint: disable=import-error
import time
from serialization import (  # type: ignore # pylint: disable=import-error
    init_serialization,
)
from threading import Lock
from typing import List, Tuple

REMOTE_LOG = "remote.log"
TCLI_LOG = "tcli.log"
MOOSE_LOGS_DIR = "/moose_logs"

# This call will allow the remote-side of the Pyro5 connection to handle types defined in libtelio.udl
init_serialization(libtelio)


def serialize_error(f):
    fname = str(f).split(" ")[1]

    def wrap(*args, **kwargs):
        args_str = ", ".join(map(str, args[1:]))
        with open(REMOTE_LOG, "a", encoding="utf-8") as logfile:
            try:
                res = f(*args, **kwargs)
                logfile.write(
                    f"{datetime.datetime.now()} {fname}({args_str}) => {res}\n"
                )
                return (res, None)
            except libtelio.TelioError as e:
                logfile.write(
                    f"{datetime.datetime.now()} {fname}({args_str}) -> {str(e)}\n"
                )
                return (None, str(e))

    return wrap


class TelioEventCbImpl(libtelio.TelioEventCb):
    def __init__(self):
        self._events: list[Tuple[float, libtelio.Event]] = []

    def event(self, payload):
        self._events.append((time.time(), payload))

    def next_event(self) -> Tuple[float, libtelio.Event] | None:
        if len(self._events) > 0:
            return self._events.pop(0)
        return None


class TelioLoggerCbImpl(libtelio.TelioLoggerCb):
    def __init__(self, logfile):
        self.lock = Lock()
        self.logfile = logfile

    def _do_log(self, log_level, payload):
        start_ts = time.time()
        with self.lock:
            lock_acquired_ts = time.time()
            self.logfile.write(f"{datetime.datetime.now()} {log_level} {payload}\n")
        end_ts = time.time()
        return (start_ts, lock_acquired_ts, end_ts)

    def log(self, log_level, payload):
        (start_ts, lock_acquired_ts, end_ts) = self._do_log(log_level, payload)
        if end_ts - start_ts > 0.5:
            self._do_log(
                libtelio.TelioLogLevel.WARN,
                f"Dumping log line took too long: {start_ts} {lock_acquired_ts} {end_ts}",
            )


@Pyro5.api.expose
@Pyro5.server.behavior(instance_mode="single")
class LibtelioWrapper:
    def __init__(self, daemon, logfile):
        self._daemon = daemon

        self._libtelio = None
        self._event_cb = TelioEventCbImpl()
        self._logger_cb = TelioLoggerCbImpl(logfile)
        libtelio.add_timestamps_to_logs()
        libtelio.set_global_logger(libtelio.TelioLogLevel.DEBUG, self._logger_cb)

    def shutdown(self):
        if self._libtelio is not None:
            self._libtelio.shutdown()
        self._daemon.shutdown()

    @serialize_error
    def create(self, features: libtelio.Features):
        self._libtelio = libtelio.Telio(features, self._event_cb)

    @serialize_error
    def next_event(self) -> libtelio.Event:
        return self._event_cb.next_event()

    @serialize_error
    def stop(self):
        self._libtelio.stop()

    @serialize_error
    def start_named(self, private_key, adapter, name: str):
        self._libtelio.start_named(
            private_key, libtelio.TelioAdapterType(adapter), name
        )

    @serialize_error
    def start_named_ext_if_filter(
        self, private_key, adapter, name: str, ext_if_list: List[str]
    ):
        self._libtelio.start_named_ext_if_filter(
            private_key, libtelio.TelioAdapterType(adapter), name, ext_if_list
        )

    @serialize_error
    def create_tun(self, tun_id: int) -> int:
        return create_tun(tun_id)

    @serialize_error
    def start_with_tun(self, private_key, adapter, tun: int):
        self._libtelio.start_with_tun(
            private_key, libtelio.TelioAdapterType(adapter), tun
        )

    @serialize_error
    def set_fwmark(self, fwmark: int):
        self._libtelio.set_fwmark(fwmark)

    @serialize_error
    def set_ext_if_filter(self, ext_if_list: List[str]):
        self._libtelio.set_ext_if_filter(ext_if_list)

    @serialize_error
    def set_tun(self, tun: int):
        self._libtelio.set_tun(tun)

    @serialize_error
    def notify_network_change(self):
        self._libtelio.notify_network_change("")

    @serialize_error
    def connect_to_exit_node(self, public_key, allowed_ips: str, endpoint: str):
        self._libtelio.connect_to_exit_node_with_id(
            "natlab", public_key, allowed_ips, endpoint
        )

    @serialize_error
    def connect_to_exit_node_pq(self, public_key, allowed_ips: str, endpoint: str):
        self._libtelio.connect_to_exit_node_postquantum(
            "natlabpq", public_key, allowed_ips, endpoint
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
    def set_meshnet(self, cfg: libtelio.Config):
        self._libtelio.set_meshnet(cfg)

    @serialize_error
    def set_meshnet_off(self):
        self._libtelio.set_meshnet_off()

    @serialize_error
    def set_secret_key(self, secret_key):
        self._libtelio.set_secret_key(secret_key)

    @serialize_error
    def is_running(self) -> bool:
        return self._libtelio.is_running()

    @serialize_error
    def trigger_analytics_event(self) -> None:
        self._libtelio.trigger_analytics_event()

    @serialize_error
    def trigger_qos_collection(self) -> None:
        self._libtelio.trigger_qos_collection()

    @serialize_error
    def receive_ping(self) -> str:
        return self._libtelio.receive_ping()

    @serialize_error
    def flush_logs(self):
        self._logger_cb.logfile.flush()


def main():
    object_name = sys.argv[1]
    container_ip = sys.argv[2]
    port = int(sys.argv[3])

    # Cleanup old log files if any exists
    try:
        os.remove(TCLI_LOG)
        os.remove(REMOTE_LOG)
        shutil.rmtree(MOOSE_LOGS_DIR)
    except FileNotFoundError:
        pass

    try:
        with open(TCLI_LOG, "a", encoding="utf-8") as logfile:
            daemon = Pyro5.server.Daemon(host=container_ip, port=port)
            _, port = daemon.sock.getsockname()
            print(f"libtelio-port:{port}")
            sys.stdout.flush()

            wrapper = LibtelioWrapper(daemon, logfile)
            daemon.register(wrapper, objectId=object_name)

            try:
                daemon.requestLoop()
            finally:
                libtelio.unset_global_logger()
            daemon.close()
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"libtelio_remote error: {e}")
        raise e


def create_tun(tun_id: int) -> int:
    if os.name != "posix":
        return 0

    # This can't be imported on all platforms, since it's not present on Windows
    import fcntl  # pylint: disable=import-outside-toplevel

    # Check if running on macOS
    if sys.platform == "darwin":
        # macOS uses system socket interface to create utun devices
        fd = socket.socket(socket.PF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)

        # Prepare the control info structure
        # see: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/net/if_utun.h#L51
        CTLIOCGINFO = 0xC0644E03  # From <sys/ioctl.h>
        UTUN_CONTROL_NAME = "com.apple.net.utun_control"

        # Create a struct to hold control information
        # see: https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/kern_control.h#L111-L121
        info = struct.pack("I96s", 0, UTUN_CONTROL_NAME.encode())

        # Get the control ID
        info = fcntl.ioctl(fd, CTLIOCGINFO, info)
        ctrl_id = struct.unpack("I96s", info)[0]

        fd.connect((ctrl_id, tun_id + 1))

        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)

        fd_num = fd.fileno()
        fd.detach()
        return fd_num

    # Constants for TUN/TAP interface creation (from Linux's if_tun.h)
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_MULTI_QUEUE = 0x0100
    IFF_NO_PI = 0x1000
    tun_name = f"tun{tun_id}"
    tun_name_bytes = tun_name.encode("ascii")
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    # '16sH' means we need to pass 16-byte string (interface name) and 2-byte short (flags)
    ifr = struct.pack("16sH", tun_name_bytes, IFF_TUN | IFF_MULTI_QUEUE | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

    return tun_fd


if __name__ == "__main__":
    main()
