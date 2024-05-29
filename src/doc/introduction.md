# Introduction

Libtelio (pronounced 'lɪbtælɪɔ') is a client-side library for creating encrypted networks (called Meshnet) on the user's nodes.
It supports a number of features, including:

- adapting different Wireguard implementations to secure the connections,
- exit nodes which might be either VPN servers or some nodes in the Meshnet,
- "DNS" which allows name resolution in Meshnets for devices which does not support lookup tables,
- adjustable firewall.

## Quick Links

- Telio integration [documentation][_telio_integration_documentation]

## Using the libtelio API

See [this documentation module][_telio_integration_documentation] for notes on how to integrate Libtelio into an application using one of the different supported languages.

### Initializing the telio device

The main component of the Libtelio library is the `telio::Device` structure and its methods.
Let's go through the most important ones.

The first of them is the expected function `::new`.
It takes three arguments, let's describe them briefly:
 - [`features`](telio_model::features::Features) - tells Libtelio which of the additional features should be enabled - the
 description of them is out of the scope of this README
 - `event_cb` - event handler, takes a [`Box<Event>`][telio_model::event::Event], which will be called by Libtelio to handle
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

```rust no_run
use telio_model::features::Features;
use telio_model::event::Event;

let (sender, receiver) = std::sync::mpsc::channel::<Box<Event>>();

let mut device = telio::device::Device::new(
    Features::default(),
    move |e| {
        sender.send(e).unwrap();
    },
    None,
).unwrap();

// ...

loop {
    let event = receiver.recv().unwrap();
    match *event {
        Event::Node { body: Some(b) } => println!(
            "event node: {:?}:{};  Path = {:?}",
            b.state,
            b.public_key,
            b.path
        ),
        _ => {}
    };
}
```

### Starting the Telio device

Once the device is initialized we can start it, so it will create a new network
interface in your OS. This might be done using `start` method.
We need to provide an instance of the `DeviceConfig` structure:

```rust no_run
use telio_wg::AdapterType;
use telio_crypto::SecretKey;
use telio_wg::Tun;

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

```rust no_run
use telio_model::{features::Features, event::Event};

let (sender, receiver) = std::sync::mpsc::channel::<Box<Event>>();

let mut device = telio::device::Device::new(
    Features::default(),
    move |e| {
        sender.send(e).unwrap();
    },
    None,
).unwrap();

let config = telio::device::DeviceConfig {
    private_key: telio_crypto::SecretKey::gen(),
    ..Default::default()
};

device.start(&config).unwrap();
```

To stop the device we can simply call the argumentless `Device::stop` method.

### Creating a Meshnet

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

```rust no_run
use telio_model::{config::Config, features::Features, event::Event};
# // Leaving this hidden, since there's no point in pasting the whole config here.
# let serialized_config: &str = "";

let config = telio::device::DeviceConfig {
    private_key: telio_crypto::SecretKey::gen(),
    ..Default::default()
};

let (sender, receiver) = std::sync::mpsc::channel::<Box<Event>>();

let mut device = telio::device::Device::new(
    Features::default(),
    move |e| {
        sender.send(e).unwrap();
    },
    None,
).unwrap();

let config: Config = serde_json::from_str(&serialized_config).unwrap();

device.set_config(&Some(config)).unwrap();
```

To turn the Meshnet off, we need to just call `Device::set_config` with `None`.

### Selecting an exit node

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

```rust no_run
use telio_model::{event::Event, mesh::{IpNetwork, ExitNode}};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use telio::crypto::PublicKey;

// A very simplified function which returns example values for the public key, IP and port of the VPN server.
fn find_server() -> (PublicKey, SocketAddr)
{
    (PublicKey::default(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820))
};

let (sender, receiver) = std::sync::mpsc::channel::<Box<Event>>();

let mut device = telio::device::Device::new(
    telio_model::features::Features::default(),
    move |e| {
        sender.send(e).unwrap();
    },
    None,
).unwrap();

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

