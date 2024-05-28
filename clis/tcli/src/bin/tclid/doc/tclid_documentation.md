# TCLID

A daemonized version of TCLI, which can be used in scripts.

## How To Build TCLID

Currently TCLID is implemented as a package of the libtelio project, just like TCLI, so it is build just like TCLI too:

```shell
cargo build -p tcli --bin tclid
```

### Building The Documentation

The full documentation for TCLID can be built with the following command:

```shell
cargo doc -p tcli --bin tclid --open --no-deps --document-private-items
```

## How To Use TCLID

The usage of TCLID is the same as TCLI with one main difference: **TCLID works in the background so there's no need for an STDIO interface**

So instead of running a TCLI executable and then writing TCLI commands into the STDIO based CLI you write `<path to tclid executable> <TCLI command>` directly into your terminal **or from a script**.

Here's an example of how to run meshnet using TCLID:

```shell
./tclid mesh on tun10
```

You can also use TCLID directly through cargo to build and run using only one command:

```shell
cargo run -p tcli --bin tclid -- mesh on tun10
```

See `example_vpn_enable_linux.sh` and `example_vpn_disable_linux.sh` for examples on how to use TCLID in a script.

### How To Start TCLID Daemon

The TCLID daemon is started when running any command (except for `quit` for obvious reasons), or even no commands so you don't really need to worry about starting it manually.

So if you want to just start the TCLID daemon, run:

```shell
./tclid
```

### How To Stop TCLID

Because TCLID runs as a daemon in the background it needs to be stopped manually using the same `quit` command which is used by TCLI.

So TCLID can be stopped by running:

```shell
./tclid quit
```

>NOTE: If due to a bug the daemon fails to stop using the `quit` command, you can run `sudo cat /var/run/tclid_wd/tclid.pid | sudo xargs kill -9` from the root of the libtelio repo (or wherever the tclid.pid fie is visible from).

### Feature Flags

Feature flags are specified by putting the -f flag as a json string with no whitespaces:

```shell
./target/debug/tclid -f '{"direct":{}}'
```

>NOTE: Feature flags can only be set when starting the daemon, so if it's already running, you'll need to stop it first.

### Help

Help command works the same way as with TCLI and will not start the TCLID daemon.

So if you want to find out how to use the device connect command, run:

```shell
./target/debug/tclid dev con --help
```

## Logs

Logs along with other files related to TCLID can be found at `/var/run/tclid_wd/` directory.

## Platform Support

- Linux is supported and tested.
- MacOS is supported, but not tested.
- Windows is not supported yet.

## Compatibility

All of the examples given here were tested with:

- rustc 1.77.2 (25ef9e3d8 2024-04-09)
- cargo 1.77.2 (e52e36006 2024-03-26)
- rustdoc 1.77.2 (25ef9e3d8 2024-04-09)
