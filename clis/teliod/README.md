### Building Teliod

For typical Linux environment it might be built using simply:

```cargo build```

For OpenWRT you might need a bit more complex command, including your router architecture and the fact the OpenWRT is MUSLE-based, for example:

```CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld CC=/path/to/arm-linux-gnueabi-gcc cargo build --package teliod --target armv7-unknown-linux-musleabihf```

You may need to download some sufficient MUSLE toolchains from `musle.cc`.

### Using Teliod daemon

Teliod runs Telio library in the background and provides a simple CLI tool to manage it.
There is a command for running the daemon:
 - `teliod daemon <path_to_config_file>` - starts the daemon. The config file should be provided in a JSON format (see `example_teliod_config.json` file). Currently supported configuration variables:
   - `log_level` - filters the logged messages by priority, possible levels:
     - `error`
     - `warn`
     - `info`
     - `debug`
     - `trace`
     - `off`
   - `log_file_path` - a path to the daemon's logging file (relative paths are starting in Teliod's working directory)
   - `authentication_token` - Token from Nord VPN account to authenticate API calls
   - `app_user_uid` - A unique number for each user of the application
   - `interface_name` - Name of tunnel interface to connect to. Note that for macOS the name has to be in form `tun#` where `#` can be any integer number
   - `interface_config_provider` - Provider for configuring the interface address, possible options:
     - `manual` - do not configure interfaces automatically
     - `ifconfig` - systems using ifconfig command
     - `iproute` - systems using iproute2 command

And following cli commands:
 - `teliod get-status` - returns the status of teliod and the meshnet peer list
