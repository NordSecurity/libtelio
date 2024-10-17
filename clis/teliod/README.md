### Building Teliod

For typical Linux environment it might be built using simply:

```cargo build```

For OpenWRT you might need a bit more complex command, including your router architecture and the fact the OpenWRT is MUSLE-based, for example:

```CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld CC=/path/to/arm-linux-gnueabi-gcc cargo build --package teliod --target armv7-unknown-linux-musleabihf```

You may need to download some sufficient MUSLE toolchains from `musle.cc`.

### Using Teliod daemon

Teliod runs Telio library in the background and provied a simple CLI tool to manage it.
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

And following cli commands:
 - `teliod hello-world <NAME>` - simple command for testing purposes, logs "Hello NAME!", used to ensure daemon proper startup, should be erased in the future and replaced by some more serious one
