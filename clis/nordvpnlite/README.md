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

* `nordvpnlite start <path_to_config_file>` - starts the daemon.
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
* `authentication_token` - Token from Nord VPN account to authenticate API calls
* `app_user_uid` - A unique number for each user of the application
* `adapter_type` - Wireguard adapter to use, possible options:
  * `neptun` - User space implementation, available on multiple platforms
  * `linux-native` - Linux native implementation
* `interface`
  * `name` - Name of tunnel interface to connect to. Note that for macOS
  the name has to be in form `tun#` where `#` can be any integer number
  * `config_provider` - Provider for configuring the interface address,
  possible options:
    * `manual` - do not configure interfaces automatically
    * `ifconfig` - systems using ifconfig command
    * `iproute` - systems using iproute2 command
    * `uci` - OpenWRT systems using uci command
* `vpn` - VPN config type. If omitted, 'recommended' type is chosen. Possible options:
  * `server` - manually specified endpoint:
    * `address` - The IP address of the server/endpoint to connect to
    * `public_key` - The public key of the server/peer to connect to
  * `country` - Full country name or ISO A2 code, of the desired VPN server location.
  * `recommended` - First server from the API recommendation list will be selected.
* `dns` - Optional list of DNS server IP addresses to use. If not set, built-in safe defaults are used.

And following cli commands:

* `nordvpnlite get-status` - returns the status of nordvpnlite and the VPN connection
* `nordvpnlite is-alive` - query if the daemon is running
* `nordvpnlite quit-daemon` - stop daemon execution
