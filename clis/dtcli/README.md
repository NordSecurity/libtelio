in case the communication with the daemon process dies and the process keeps running, a quick way to stop it is `sudo cat daemon/dtcli.pid | sudo xargs kill -9`. Run this from the root of the libtelio repo.

## How To Build DTCLI

Currently DTCLI is implemented as a package of the libtelio project, just like TCLI, so it is build just like TCLI too:

```
cargo build -p dtcli
```

## How To Use DTCLI

The usage of DTCLI is the same as TCLI with one main difference: **DTCLI works in the background so there's no STDIO interface**

So instead of running a TCLI executable and then writing TCLI commands into the STDIO based CLI you write `<path to dtcli executable> <TCLI command>` directly into your terminal.

Unlike TCLI this allows you to control libtelio using scripts.

Here's an example of how to start meshnet using DTCLI:

```
./dtcli mesh on tun10
```

As you can see the command syntax used with DTCLI is the same as TCLI (except for a few exceptions which will be covered below)

You can also use DTCLI directly through cargo to build and run using only one command:

```
cargo run -p dtcli -- mesh on tun10
```

See `example_vpn_enable.sh` and `example_vpn_disable.sh` for examples on how to use DTCLI in a script.

## Usage Limitations

### Features

Features must be specified by putting the -f flag right after the dtcli path and then adding the feature json string with no other commands:

```
./target/debug/dtcli -f '{"direct":{}}'
```

Features are set for the daemon and in order to change the feature configuration you need to stop the daemon and start it again as shown above.

### Help

Detailed help information now only works if the help argument is put in front of the command. For example if you want to see the help regarding the connect command, you run:

```
./target/debug/dtcli help dev con
```

If you run the help command in the old way like below, you'll still see the command output, but that will start the daemon.

```
./target/debug/dtcli dev con --help
```

## How To Start DTCLI Daemon

The DTCLI daemon is automatically started when running any command (except for `quit` for obvious reasons), so you don't need to worry about starting it manually.

>NOTE: Running ./dtcli help currently also starts the daemon.

But if for any reason you want to start DTCLI daemon manually without running any telio commands, you can also do that by just running the DTCLI executable without any arguments:

```
./dtcli
```

## How To Stop DTCLI

Because DTCLI runs as a daemon in the background it needs to be stopped manually using the same `quit` command which is used by TCLI.

So DTCLI can be stopped by running:

```
./dtcli quit
```

>NOTE: If due to a bug the daemon fails to stop using the `quit` command, you can run `sudo cat daemon/dtcli.pid | sudo xargs kill -9` from the root of the libtelio repo (or wherever the dtcli.pid fie is visible from).