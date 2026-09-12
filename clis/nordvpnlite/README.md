# NordVPN Lite

**NordVPN Lite** is a lightweight, standalone VPN client built around
the `libtelio` library.

It is designed for embedded and edge environments, that are too resource
constrained for the full NordVPN application.

## Core functionality

* Provides VPN related functionalities.
* Minimal user interaction, controlled via a single configuration file.
* Automated network and routing configuration.
* VPN servers fetched dynamically using NordVPN API.

## Building NordVPN Lite

For typical Linux environment it might be built using simply:

```cargo build```

For OpenWRT you might need a bit more complex command, including your router architecture
and the fact the OpenWRT is MUSLE-based, for example:

```CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld CC=/path/to/arm-linux-gnueabi-gcc cargo build --package nordvpnlite --target armv7-unknown-linux-musleabihf```

You may need to download some sufficient MUSLE toolchains from `musle.cc`.

## Using NordVPN Lite

NordVPN Lite runs Telio library in the background and provides a simple CLI tool to
manage it.

There is a command for running the daemon:

* `nordvpnlite start` - starts the daemon.
  * `--config-file <path_to_config_file>` - specify alternative configuration file,
  * `--no-detach` - run the nordvpnlite in the foreground as a regular process,
  without detaching from the terminal.
  * `--stdout-path` - Redirect daemon standard output to the specified file,
  Defaults to `/var/log/nordvpnlite.log`, ignored when used with `--no-detach`
  Some early logs may still be printed to stdout before redirection.
  * `--working-directory` - Specifies the daemons working directory,
  Defaults to `/`, ignored when used with `--no-detach`

The config file should be provided in a JSON format
(see `example_nordvpnlite_config.json` file).

Currently supported configuration variables:

* `auth_file_path` - Path to the file where the authentication token is stored,
  defaults to `/etc/nordvpnlite/auth.json`. Use the `login`/`logout` commands
  (see below) to manage its contents rather than editing it directly. The
  `NORD_TOKEN` environment variable, when set to a valid token, takes precedence
  over this file.
* `vpn` - VPN config type. If omitted, 'recommended' type is chosen. Possible options:
  * `server` - manually specified endpoint:
    * `address` - The IP address of the server/endpoint to connect to
    * `public_key` - The public key of the server/peer to connect to
  * `country` - Full country name or ISO A2 code, of the desired VPN server location.
  * `recommended` - First server from the API recommendation list will be selected.
* `post_quantum` - If `true`, use a post-quantum-secure (Kyber + X25519) key
  exchange. Defaults to `false`.
* `log_level` - filters the logged messages by priority, possible levels:
  * `error`
  * `warn`
  * `info`
  * `debug`
  * `trace`
  * `off`
* `log_file_path` - a path to store the daemon's logs,
needs be absolute, otherwise will be relative to `working-directory` when daemonized
* `log_file_count` - number of recent log files (log files are rotated daily)
* `app_user_uid` - A unique number for each user of the application
* `adapter_type` - Wireguard adapter to use, possible options:
  * `neptun` - User space implementation, available on multiple platforms
  * `linux-native` - Linux native implementation
* `interface`
  * `name` - Name of tunnel interface to connect to. Note that for macOS
  the name has to be in form `tun#` where `#` can be any integer number
  * `max_route_priority` - Optional maximum routing rule priority value, if
  not set the next available values before `from all lookup main` will be used
  * `config_provider` - Provider for configuring the interface address,
  possible options:
    * `manual` - do not configure interfaces automatically
    * `iproute` - systems using iproute2 command
    * `uci` - OpenWRT systems using uci command
  * `manage_dnsmasq` - Only used by the `uci` provider. If `true` (the default), the
  daemon points dnsmasq at the `dns` servers (`dhcp.@dnsmasq[0].noresolv` and `.server`,
  replacing existing entries such as split-DNS forwards) and advertises the tunnel MTU
  to LAN clients, restoring both on a clean shutdown. Set to `false` to leave
  `/etc/config/dhcp` untouched
* `dns` - Optional list of DNS server IP addresses to use. If not set, built-in safe defaults are used.
  Ignored when `interface.manage_dnsmasq` is `false`
* `health_check` - Optional active tunnel health check (Linux only), disabled by default:
  * `enabled` - `true` to turn it on. Defaults to `false`
  * `interval_seconds` - seconds between probes. Defaults to `15`
  * `probe_timeout_seconds` - seconds before a probe counts as failed. Defaults to `5`
  * `failure_threshold` - consecutive failed tunnel probes, while the uplink works,
  before switching server. Defaults to `4`
  * `settle_seconds` - seconds to wait after connecting or switching before probing
  again. Defaults to `30`
  * `probe_targets` - TCP `address:port` endpoints; a probe succeeds if any of them
  accepts a connection. Defaults to `1.1.1.1:443`, `8.8.8.8:443` and `9.9.9.9:443`
  * `wan_interface` - uplink interface for the comparison probe. Detected from the
  default route if not set

  Each probe opens a TCP connection through the tunnel interface. When that fails, the
  probe is repeated through the uplink, and only a failing tunnel with a working uplink
  counts towards `failure_threshold`, so an ISP outage does not cause server switching.
  The next server is taken from the list fetched at startup, because the API may be
  unreachable while the tunnel is down. With a fixed `vpn.server`, the daemon reconnects
  to that server instead.

And following cli commands:

* `nordvpnlite status` - returns the status of nordvpnlite and the VPN connection
* `nordvpnlite is-alive` - query if the daemon is running
* `nordvpnlite stop` - stop daemon execution
* `nordvpnlite reload` - reload the configuration file and restart the daemon
* `nordvpnlite countries` - list countries with available VPN servers
* `nordvpnlite login <token>` (or `nordvpnlite login --token <token>`) - store the authentication token obtained
  from [my.nordaccount.com](https://my.nordaccount.com) into the auth file
  (`auth_file_path`). Overwrites any previously stored token.
  * `--config-file <path>` - use an alternative configuration file
  (defaults to `/etc/nordvpnlite/config.json`)
* `nordvpnlite logout` - remove the stored authentication token (auth file).
  * `--config-file <path>` - use an alternative configuration file
  (defaults to `/etc/nordvpnlite/config.json`)

## OpenWRT

After installing the `.ipk` package:

* Store your authentication token obtained from [my.nordaccount.com](https://my.nordaccount.com) by running `nordvpnlite login <token>` (or `nordvpnlite login --token <token>`) (it is saved to the `auth_file_path` configured in `/etc/nordvpnlite/config.json`, by default `/etc/nordvpnlite/auth.json`)
* To start the `nordvpnlite` service run `/etc/init.d/nordvpnlite start`
* After each edit of `/etc/nordvpnlite/config.json` reload the service with `/etc/init.d/nordvpnlite reload`
* To stop the `nordvpnlite` service run `/etc/init.d/nordvpnlite stop`. Important: Simply running `nordvpnlite stop` will cause procd to respawn it
* To toggle running `nordvpnlite` automatically at boot (respawning), enable or disable the service `/etc/init.d/nordvpnlite enable` or `/etc/init.d/nordvpnlite disable`
* To read the service logs run `logread | grep -i nordvpnlite` and `cat /var/log/nordvpnlite.log`
