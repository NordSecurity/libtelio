# libtelio

![CI status](https://github.com/NordSecurity/libtelio/actions/workflows/gitlab.yml/badge.svg?branch=main)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/NordSecurity/libtelio/badge)](https://securityscorecards.dev/viewer/?uri=github.com/NordSecurity/libtelio)

## Overview
Libtelio (pronounced 'lɪbtælɪɔ') is a client-side library for creating encrypted networks (called Meshnet) on the user's nodes.
It supports a number of features, including:
 - adapting different Wireguard implementations to secure the connections,
 - exit nodes which might be either VPN servers or some nodes in the Meshnet,
 - "DNS" which allows name resolution in Meshnets for devices which does not support lookup tables,
 - adjustable firewall.

## Getting started

### Prerequisites

In the latter sections of this README we assume (if it's not explicitly assumed otherwise)
that you are working on a Linux machine. To be able to build `libtelio`
it is enough to have [rust](https://www.rust-lang.org/tools/install) installed.
To go through the short TCLI tutorial you need also [docker](https://docs.docker.com/engine/install).

### Build

You can build the `libtelio` library using standard `cargo build` command.

#### Linux toolchain
1. Verify that GCC (GNU Compiler Collection) has been installed:
```shell
gcc --version
```
Otherwise run following command to install it:
```shell
sudo apt update
sudo apt install gcc
```

#### Windows msvc toolchain

To build `libtelio` on Windows with `x86_64-pc-windows-msvc` toolchain you need to install:
1. Visual Studio 2019/2022
2. Additional Visual Studio components:
a. Desktop development with C++
b. Python 3 64-bit
c. C++ Clang tools for Windows
3. TDM-GCC 64-bit (https://jmeubank.github.io/tdm-gcc/download/)
4. Go 1.19

Before running `cargo build` you need to set msvc environment. Examples for cmd and powershell in case of Visual Studio 2019 Community:
1. In cmd.exe run:
```shell
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" x64
```
2. In powershell run:
```shell
Import-Module "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" -SkipAutomaticLocation
```

### Setting up Meshnet with tcli

`tcli` is a simple shell created to test and discover the `libtelio` library capabilities.
Let's see how to use it to create a simple mesh connection between two docker containers.

First of all, build `tcli` utility:
```
cargo build -p tcli
```

You will need a lightweight Linux docker image with the some networking utilities,
which are missing from the basic Ubuntu image, so let's create a new one.
Make a `docker` directory in `tcli-test` and put there the following simple Dockerfile:
```
FROM ubuntu

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 iputils-ping tcpdump ca-certificates
```

Then build it and tag it as `tcli-test`, running the following command from the `docker` directory:
```
docker build -t tcli-test .
```
When the image is built, you need to run two copies of it, one for `t1`:
```
docker run -itd -v <path to libtelio top-level-directory>:/hostfs --name=t1 --hostname=t1 --privileged tcli-test bash
```
and a second one for `t2`:
```
docker run -itd -v <path to libtelio top-level-directory>:/hostfs --name=t2 --hostname=t2 --privileged tcli-test bash
```

You need to prepare four terminals. In two of them (we will refer to them as `T1a` and `T1b`)
run the following command to connect to the container `t1`:
```
docker exec -it t1 bash
```
and then run an analogous command for `t2` in another two (`T2a` and `T2b`):
```
docker exec -it t2 bash
```

In the following steps, you will need a token for your NordVPN account
(if you don't have an account, you need to create one),
which you can generate from `https://my.nordaccount.com/dashboard/nordvpn/`.

In terminals `T1a` and `T2a` run `tcli`:
```
hostfs/target/debug/tcli
```
and in both of the opened `tcli`s:
```
login token <NORDVPN_TOKEN>
mesh on <NAME>
```
where `<NORDVPN_TOKEN>` is the token generated for your NordVPN account and
`<NAME>` is `t1` for `T1a` and `t2` for `T2a`.

There will be a large JSON config printed - the IP address can be found in
the list `"ip_addresses"`:
<pre>
>>> mesh on t1
- registered new device.
- got config:
{"identifier":"...","public_key":"...","hostname":"...","os":"linux","os_version":"linux tcli",<span style="color:red">"ip_addresses":["..."]</span>,"traffic_routing_supported":false,"endpoints":["..."],...
</pre>

When you find it set it in your bash terminals
(set the one found in config in `T1a` in `T1b` and the one from `T2a` in `T2b`):
```
ip addr add <IP_ADDRESS>/10 dev <NAME>
ip -6 addr add <IPv6_ADDRESS>/64 dev <NAME>
ip link set up dev <NAME>
ip link set dev <NAME> mtu 1420
```
Note: for meshnet to work, you do not need both IPv4 and IPv6 addresses to be set. Only one of them should be enough.

Currently, there is one more issue to overcome: because node `t1` was connected
earlier, it doesn't have the information about node `t2`.
Run `mesh on t1` in `T1a` to fix it.

The containers should be now connected by the mesh, so to try the connection,
run `ping` in `T1b` and `tcpdump` in `T2b` and see how the packages are flowing.

##### Running meshnet on macOS

To run tcli client on native macOS use utun name for interface name instead of t1/t2.
Use unique index for utun since there might be some already present.
```
>>> login token <NORDVPN_TOKEN>
>>> mesh on utun10
```

Find meshnet ip address from "ip_addresses" field the same as in linux case. Then
```
ifconfig utun10 add <IP_ADDRESS>/10 <IP_ADDRESS>
ifconfig inet6 utun10 add <IPv6_ADDRESS> prefixlen 64
ifconfig utun10 mtu 1420
route add 100.64/10 <IP_ADDRESS>
route add -inet6 fd74:656c:696f::/64 <IPv6_ADDRESS>
```

### Using the libtelio API

#### Initializing the telio device

The main component of the Libtelio library is the `telio::Device` structure and its methods.
Let's go through the most important ones.

The first of them is the expected function `::new`.
It takes three arguments, let's describe them briefly:
 - `features` - tells Libtelio which of the additional features should be enabled - the
 description of them is out of the scope of this README
 - `event_cb` - event handler, takes a `Box<Event>`, which will be called by Libtelio to handle
 events of three types:
   - `Error` - an error occurs, especially urgent are Critical error events, which means
   that the library is unable to continue running and it requires a call to `hard_reset` method
   - `Relay` - when the relay (i.e. Derp) server configuration is changed, contains
   a JSON with a new one
   - `Node` - appears when the Meshnet node's configuration is changed, it contains
   a JSON with a new one
 - `protect` - callback for excluding connections from VPN tunnel (currently used only for android).

`telio::Device` implements `Drop` trait, so we don't need to worry
about deinitialization in the end.
Let's look at an example initialization of `telio::Device` with no additional
features, handling only `Node` events and not using `protect` callback:

```
let (sender, receiver) = mpsc::channel::<Box<Event>>();

let mut device = telio::device::Device::new(
    Features::default(),
    move |e| {
        sender.send(e).unwrap();
    },
    None,
).unwrap();

...

loop {
    let event = receiver.recv().unwrap();
    match *event {
        Event::Node { body: Some(b) } => println!(
            "event node: {:?}:{};  Path = {:?}",
            b.state.unwrap(),
            b.public_key,
            b.path
        ),
        _ => {}
    };
}
```

#### Starting the Telio device

Once the device is initialized we can start it, so it will create a new network
interface in your OS. This might be done using `start` method.
We need to provide an instance of the `DeviceConfig` structure:
```
pub struct DeviceConfig {
    pub private_key: SecretKey,
    pub adapter: AdapterType,
    pub name: Option<String>,
    pub tun: Option<Tun>,
}
```

Let's discuss its fields shortly:
 - `private_key` a `telio::crypto::SecretKey` instance containing a 256-bit key,
 - `adapter` indicating which Wireguard implementation we want to use,
 - `name` is the name of the network interface, when omitted, Telio uses the default one,
 - `tun` a file descriptor of the already opened tunnel, if it's not provided Telio will open a new one.

The API provides a default config which is almost sufficient for simple cases,
the only need that needs to be done is the generation of a private key:
```
let config = DeviceConfig {
    private_key: SecretKey::gen(),
    ..Default::default()
};
device.start(&config).unwrap();
```

To stop the device we can simply call the argumentless `Device::stop` method.

#### Creating a Meshnet

To turn on the Meshnet feature, you need to call the `Device::set_config` method
with the proper config. After logging in and registering to the desired
Derp server, the JSON with config may be downloaded from it.

In the case of using the Derp server provided by Nord, you can use a token (like the one
used in the tcli setup) passing it with a user HTTP header (in a form `token:<TOKEN>`),
to receive the necessary credentials from
`https://api.nord.com/v1/users/services/credentials`
which will return you another token, with which you may register to
`https://api.nord.com/v1/meshnet/machines`
passing the token in the authorization data: `Bearer token:<TOKEN>`.
You will be given an `ID` with which you can download the config from
`https://api.nord.com/v1/meshnet/<ID>/`
using the same bearer token.

After the device is started and the JSON config downloaded, we can
deserialize it and finally call `set_config`:
```
let config: Config = serde_json::from_str(&serialized_config).unwrap();
self.telio.set_config(&Some(config)).unwrap();
```

To turn the Meshnet off, we need to just call `Device::set_config` with `None`.

#### Selecting an exit node

The other thing you may do with the started device is to set up an exit node.
It might be either one of the nodes in your internal network, or
some VPN server compatible with Wireguard. To connect to them, we need
their public key and endpoint.

If we want to use the NordVPN server, we can obtain them from the JSON
downloaded from
`https://api.nordvpn.com/v1/servers/recommendations`.
The received JSON is rather big, so to get the needed fields
you can extract the `telio::tcli::nord::find_server` method and simplify
it a bit to just return a pair of `public_key` and `endpoint`.
When you have it, setting up the VPN connection is fairly simple:

```
let (public_key, endpoint) = find_server();
let exit_node = ExitNode {
    identifier: "fa5bbe9b-338b-4bd2-8c97-166ceee65790".to_owned(),
    public_key,
    allowed_ips: Some(vec![IpNetwork::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        0,
    )
    .unwrap()]),
    endpoint: Some(endpoint),
};
device.connect_exit_node(&exit_node);
```

## Testing

For now, unit tests and integration tests are supported on Linux. All tests run on CI for every
merge request. Code can't be merged unless builds and tests pass.

Unit tests ensure internal components are working fine. Unit tests *probably* also pass on MacOS.
```
cargo test
```

## Releases

For information about how to release, please see [releasing.md](releasing.md).

## Building Documentation

Documentation for Libtelio is currently built and deployed to GitHub Pages by manually triggering the build-and-deploy-docs job on the pipeline in GitHub Actions. If you need to build the rustdocs locally, reference the gh-pages CI file and don't forget to set the RUSTDOCFLAGS env variable accordingly.

## Contributions

For information about how to contribute, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[This project is licensed under the terms of the GNU General Public License v3.0 only](LICENSE)
