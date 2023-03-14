# libtelio

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
that you are working on a Linux machine and that you have installed:
 - [docker](https://docs.docker.com/engine/install),
 - git,
 - python3,
 - pip,
 - quilt and
 - [rust](https://www.rust-lang.org/tools/install).

### Build

If the prerequisites are ready, you can build the library simply using
`cargo build` command.

### Setting up Meshnet with tcli

`tcli` is a simple shell created to test and discover the `libtelio` library capabilities.
Let's see how to use it to create a simple mesh connection between two docker containers.

First of all, build `tcli` utility:
```
cargo build -p tcli
```

You will need a basic Linux docker image with the basic networking utilities,
which are missing from the basic Ubuntu image, so let's create a new one.
Make a `docker` directory in `tcli-test` and put there the following simple Dockerfile:
```
FROM ubuntu

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 iputils-ping tcpdump
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
ip addr add <IP_ADDRESS> dev <NAME>
ip link set up dev <NAME>
ip link set dev <NAME> mtu 1420
```

Currently, there is one more issue to overcome: because node `t1` was connected
earlier, it doesn't have the information about node `t2`.
Run `mesh on t1` in `T1a` to fix it.

The containers should be now connected by the mesh, so to try the connection,
run `ping` in `T1b` and `tcpdump` in `T2b` and see how the packages are flowing.

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
Let's look at an example initialization of `telio::Device`
which uses only a simple logger logging to `stderr`, no additional
features, handles only `Node` events and doesn't set `protect` callback:

```
let decorator = slog_term::PlainDecorator::new(io::stderr());
let drain = slog_term::FullFormat::new(decorator).build().fuse();
let drain = slog_async::Async::new(drain).build().fuse();
let logger = slog::Logger::root(drain, o!());

let (sender, receiver) = mpsc::channel::<Box<Event>>();

let mut device = telio::device::Device::new(
    Features::default(),
    logger,
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

Running integration tests is more complex and currently is out of the scope of this README.

## Contributions

For information about how to contribute, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[This project is licensed under the terms of the GNU General Public License v3.0 only](LICENSE)
