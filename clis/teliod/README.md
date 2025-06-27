# Teliod

Teliod is small Meshnet and VPN application, designed to be used in standalone
and embedded environments.

## Building Teliod

For typical Linux environments, Teliod can be built using the following commands:

```sh
# Debug build from teliod directory
cargo build

# Release build
cargo build --package=teliod --release 
```

For OpenWRT you might need to cross-compile, depending on the router architecture.

OpenWRT does not ship with GNU libc and instead is MUSL based.
And further needs to be compiled with MUSL tool-chains or statically linked.
Which can be obtained from from [musle.cc](https://musl.cc/) or the `musl-dev` package

```sh
# Add MUSL target
sudo apt install musl-dev
rustup target add --toolchain <target_architecture>-linux-musl

# Regular release build
cargo build --package=teliod --target=<target_architecture>-linux-musl --release

# Size optimized release build
cargo build --package=teliod --target=<target_architecture>-linux-musl --profile=release-size-optimized
```

## Using Teliod

Teliod runs Telio library in the background and provides a simple CLI tool to
manage it.

There is a command for running the daemon:

- `teliod start <path_to_config_file>` - starts the daemon.
  - `--no-detach` - run the teliod in the foreground as a regular process,
  without detaching from the terminal.
  - `--stdout-path` - Redirect daemon standard output to the specified file,
  Defaults to `/var/log/teliod.log`, ignored when used with `--no-detach`
  Some early logs may still be printed to stdout before redirection.
  - `--working-directory` - Specifies the daemons working directory,
  Defaults to `/`, ignored when used with `--no-detach`

The config file should be provided in a JSON format
(see `example_teliod_config.json` file).

Currently supported configuration variables:

- `log_level` - filters the logged messages by priority, possible levels:
  - `error`
  - `warn`
  - `info`
  - `debug`
  - `trace`
  - `off`
- `log_file_path` - a path to store the daemon's logs,
needs be absolute, otherwise will be relative to `working-directory` when daemonized
- `log_file_count` - number of recent log files (log files are rotated daily)
- `authentication_token` - Token from Nord VPN account to authenticate API calls
- `app_user_uid` - A unique number for each user of the application
- `adapter_type` - Wireguard adapter to use, possible options:
  - `neptun` - User space implementation, available on multiple platforms
  - `linux-native` - Linux native implementation
- `interface`
  - `name` - Name of tunnel interface to connect to. Note that for macOS
  the name has to be in form `tun#` where `#` can be any integer number
  - `config_provider` - Provider for configuring the interface address,
  possible options:
    - `manual` - do not configure interfaces automatically
    - `ifconfig` - systems using ifconfig command
    - `iproute` - systems using iproute2 command

And following cli commands:

- `teliod get-status` - returns the status of teliod and the meshnet peer list
- `teliod is-alive` - query if the daemon is running
- `teliod quit-daemon` - stop daemon execution
