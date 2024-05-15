# Documentation For Integrating Telio Into Other Languages

This document is mainly intended for NordVPN's app developers.

## Integration feature list

Note: the examples here are not using proper error handling for the sake of brevity. 

### Log Callback
App sets a global logger with log level and log callback. Reports logs to needed systems.

In version 4.x and earlier, the log level and callback was set on the telio instance, but since version 5.0, it's a separate call.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};

#[derive(Debug)]
struct Logger;
impl TelioLoggerCb for Logger {
    fn log(&self, log_level: TelioLogLevel, payload: String) {
        // report log level and payload to the app
    }
}
// Global function
set_global_logger(TelioLogLevel::Debug, Box::new(Logger));
```

```go
import github.com/nordsecurity/telio

type Logger struct {}

func (l Logger) Log(logLevel TelioLogLevel, payload string) {
    // report log level and payload to the app
}

SetGlobalLogger(TelioLogLevel.Debug, Logger{})
```

```swift
import libtelio

class Logger: TelioLoggerCb {
    func log(logLevel: TelioLogLevel, payload: String) {
        // report log level and payload to the app
    }
}

setGlobalLogger(TelioLogLevel.Debug, Logger())
```

```cs
using uniffi.libtelio;

class Logger : TelioLoggerCb {
    public void Log(TelioLogLevel logLevel, String payload) {
        // report log level and payload to the app
    }
}

SetGlobalLogger(TelioLogLevel.Debug, new Logger());
```

```kotlin
import com.nordsec.libtelio.*

val Logger = object: TelioLoggerCb {
    override fun log(logLevel: TelioLogLevel, payload: String) {
        // report log level and payload to the app
    }
}

setGlobalLogger(TelioLogLevel.Debug, Logger)
```

</multi-code>
 

### Create / Destroy

App can create and destroy Telio device.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let telio = Telio::new(Default::default(), Box::new(EventHandler)).unwrap();
telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

telio, err := Telio {...}
_, err = telio.Destroy()
```

```swift
import libtelio

let telio = Telio(...)
telio.destroy()
```

```cs
using uniffi.libtelio;

Telio telio = new Telio(...);
telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val telio = Telio.new(...)!!
telio.destroy()!!
```

</multi-code>


### Feature config

App can deserialize JSON string with feature config before passing to telio.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};
use telio_model::features::FeatureLana;

let json_feature_config = "<feature config fetched from API>".to_owned();
let mut feature_config = deserialize_feature_config(json_feature_config).unwrap();

feature_config.lana = Some(FeatureLana {  event_path: "some/path.db".to_owned(), prod: true });
if let Some(nurse) = &mut feature_config.nurse {
    nurse.fingerprint = "me".to_owned();
}

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let telio = Telio::new(feature_config, Box::new(EventHandler)).unwrap();
telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

jsonFeatureConfig := "<feature config fetched from API>";
featureConfig, err := DeserializeFeatureConfig(jsonFeatureConfig);

featureConfig.lana = FeatureLana { EventPath: "some/path.db", Prod: true}
if featureConfig.Nurse != nil {
    featureConfig.Nurse.Fingerprint = "me"
}

telio, err := Telio {
    Features: featureConfig,
    ...
}
_, err = telio.Destroy()
```

```swift
import libtelio

let jsonFeatureConfig = "<feature config fetched from API>";
let featureConfig = deserializeFeatureConfig(jsonFeatureConfig);

featureConfig.lana = FeatureLana("some/path.db", true)
featureConfig.nurse?.fingerprint = "me"

let telio = Telio(featureConfig, ...)
telio.destroy()
```

```cs
using uniffi.libtelio;

String jsonFeatureConfig = "<feature config fetched from API>";
Features featureConfig = DeserializeFeatureConfig(jsonFeatureConfig);

featureConfig.lana = new FeatureLana("some/path.db", true);
if (featureConfig.nurse != null) {
    featureConfig.nurse.fingerprint = "me";
}

Telio telio = new Telio(featureConfig, ...);
telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val jsonFeatureConfig = "<feature config fetched from API>"
val featureConfig = deserializeFeatureConfig(jsonFeatureConfig)!!

featureConfig.lana = FeatureLana("some/path.db", true)
featureConfig.nurse?.fingerprint = "me"

val telio = Telio(featureConfig, ...)!!
telio.destroy()!!
```

</multi-code>


### Event Callback
App passes event callback. Deserializes Telio Event from received JSON string. For details on events, see the [events documentation](../_telio_events_documentation/index.html).

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {
        // deserialize json payload
        // pass deserialized event to app
    }
}

Telio::new(Default::default(), Box::new(EventHandler)).unwrap();
```

```go
import github.com/nordsecurity/telio

type EventHandler struct {}

func (eh EventHandler) Event(payload String) {
    // deserialize json payload
    // pass deserialized event to app
}

_, err = Telio {
    ...,
    Events: EventHandler{},
}
```

```swift
import libtelio

class EventHandler: TelioEventCb {
    func event(payload: string) {
        // deserialize json payload
        // pass deserialized event to app
    }
}

Telio(..., EventHandler())
```

```cs
using uniffi.libtelio;

class EventHandler : TelioEventCb {
    public void Event(String payload) {
        // deserialize json payload
        // pass deserialized event to app
    }
}

new Telio(..., new EventHandler());
```

```kotlin
import com.nordsec.libtelio.*

val eventHandler = object: TelioEventCb {
    override fun event(payload: String) {
        // deserialize json payload
        // pass deserialized event to app
    }
}

new Telio(..., eventHandler)!!
```

</multi-code>
 

### Critical Recovery
If critical error event is received, Telio device should be destroyed with `telio.destroy_hard` and recreated with `Telio::new`.


### Start / Stop Default Adapter
App starts and stops Telio device instance with default adapter.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let sk = generate_secret_key();
let adapter = get_default_adapter();

let telio = Telio::new(Default::default(), Box::new(EventHandler)).unwrap();

// There are three ways to start telio:
// * start - telio does everything
// * start_with_tun - use existing tun (android, apple)
// * start_with_name - create tun with name (windows, linux)
telio.start(sk, adapter).unwrap();
telio.stop().unwrap();

telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

sk := GenerateSecretKey()
adapter := GetDefaultAdapter()

telio, err := Telio {...}

// There are three ways to start telio:
// * Start - telio does everything
// * StartWithTun - use existing tun (android, apple)
// * StartWithName - create tun with name (windows, linux)
_, err = telio.Start(sk, adapter)
_, err = telio.Stop()

_, err = telio.Destroy()
```

```swift
import libtelio

let sk = generateSecretKey()
let adapter = getDefaultAdapter()

let telio = Telio(...)

// There are three ways to start telio:
// * start - telio does everything
// * startWithTun - use existing tun (android, apple)
// * startWithName - create tun with name (windows, linux)
telio.start(sk, adapter)
telio.stop()

telio.destroy()
```

```cs
using uniffi.libtelio;

var sk = GenerateSecretKey();
var adapter = GetDefaultAdapter();

Telio telio = new Telio(...);

// There are three ways to start telio:
// * Start - telio does everything
// * StartWithTun - use existing tun (android, apple)
// * StartWithName - create tun with name (windows, linux)
telio.Start(sk, adapter);
telio.Stop();

telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val sk = generateSecretKey()
val adapter = getDefaultAdapter()

val telio = Telio.new(...)!!

// There are three ways to start telio:
// * start - telio does everything
// * startWithTun - use existing tun (android, apple)
// * startWithName - create tun with name (windows, linux)
telio.start(sk, adapter)!!
telio.stop()!!

telio.destroy()!!
```

</multi-code>

### VPN Client
App connects to/disconnects from VPN node.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use std::str::FromStr;
use ipnetwork::IpNetwork;
use telio::{ffi::*, types::*};
use telio_crypto::PublicKey;

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let sk = generate_secret_key();
let adapter = get_default_adapter();

let telio = Telio::new(Default::default(), Box::new(EventHandler)).unwrap();
telio.start(sk, adapter).unwrap();

let server_public = PublicKey::from_str("QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=").unwrap();
let server_allowed_ips = vec![IpNetwork::from_str("0.0.0.0/0").unwrap()];
let server_endpoint = "1.2.3.4:51280".parse().unwrap();
telio.connect_to_exit_node(
      server_public,
      Some(server_allowed_ips),
      Some(server_endpoint)
).unwrap();

telio.disconnect_from_exit_nodes().unwrap();
/* Connect to new exit node if there is need to change server */

telio.stop().unwrap();
telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

sk = GenerateSecretKey();
adapter = GetDefaultAdapter();

telio, err := Telio {...}
_, err = telio.Start(sk, adapter)

serverPublic := // some key, like QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=
serverAllowedIps := [1]string{"0.0.0.0/0"}
_, err := telio.ConnectToExitNode(
      serverPublic,
      serverAllowedIps,
      "1.2.3.4:51280"
)

_, err = telio.DisconnectFromExitNodes()
/* Connect to new exit node if there is need to change server */

_, err = telio.Stop()
_, err = telio.Destroy()
```

```swift
import libtelio

let sk = generateSecretKey()
let adapter = getDefaultAdapter()

let telio = Telio(...)
telio.start(sk, adapter)

let serverPublic = // some key, like QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=
telio.connectToExitNode(
      serverPublic,
      ["0.0.0.0/0"],
      "1.2.3.4:51280"
)

telio.disconnectFromExitNodes()
/* Connect to new exit node if there is need to change server */

telio.stop()
telio.destroy()
```

```cs
using uniffi.libtelio;

var sk = GenerateSecretKey();
var adapter = GetDefaultAdapter();

Telio telio = new Telio(...);
telio.Start(sk, adapter);

var serverPublic = // some key, like QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=
telio.ConnectToExitNode(
      serverPublic,
      ["0.0.0.0/0"],
      "1.2.3.4:51280"
);

telio.DisconnectFromExitNodes();
/* Connect to new exit node if there is need to change server */

telio.Stop();
telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val sk = generateSecretKey()
val adapter = getDefaultAdapter()

val telio = Telio.new(...)!!
telio.start(sk, adapter)!!

val serverPublic = // some key, like QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=
telio.connectToExitNode(
      serverPublic,
      listOf("0.0.0.0/0"),
      "1.2.3.4:51280"
)!!

telio.disconnectFromExitNodes()!!
/* Connect to new exit node if there is need to change server */

telio.stop()!!
telio.destroy()!!
```

</multi-code>

To change server, App disconnects from all exit nodes, and connects to new one.

System network configuration:

Set tunnel interface address to `10.5.0.2/16`

Route entire system traffic through tunnel interface.

Exclude server_endpoint from tunnel interface, bind it to default interface, or use system protection methods.

DNS servers set to Nord DNS servers or CyberSec servers (if needed via Telio Magic DNS forwarding).


### Meshnet Client
App turns on and off meshnet by passing Meshnet Config.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let sk = generate_secret_key();
let adapter = get_default_adapter();

let telio = Telio::new(Default::default(), Box::new(EventHandler)).unwrap();
telio.start(sk, adapter).unwrap();

let mesh_pk = generate_public_key(sk);
// Register mesh_pk with api if needed
let json_config = "<json config recieved from api>".to_owned();
let config = deserialize_meshnet_config(json_config).unwrap();
// Change secret key if needed
telio.set_secret_key(&sk).unwrap();
/* Turn on or update meshnet */
telio.set_meshnet(config).unwrap();
telio.set_meshnet_off().unwrap();

telio.stop().unwrap();
telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

sk := GenerateSecretKey()
adapter := GetDefaultAdapter()

telio, err := Telio {...}
_, err = telio.Start(sk, adapter)

meshPk := GeneratePublicKey(sk)
// Register meshPk with api if needed
jsonConfig := "<json config recieved from api>"
config, err := DeserializeMeshnetConfig(jsonConfig)
// Change secret key if needed
_, err := telio.SetSecretKey(sk)
/* Turn on or update meshnet */
_, err := telio.SetMeshnet(config)
_, err := telio.SetMeshnetOff()

_, err = telio.Stop()
_, err = telio.Destroy()
```

```swift
import libtelio

let sk = generateSecretKey()
let adapter = getDefaultAdapter()

let telio = Telio(...)
telio.start(sk, adapter)

let meshPk = generatePublicKey(sk)
// Register meshPk with api if needed
let jsonConfig = "<json config recieved from api>"
let config = deserializeMeshnetConfig(jsonConfig)
// Change secret key if needed
telio.setSecretKey(sk)
/* Turn on or update meshnet */
telio.setMeshnet(config)
telio.setMeshnetOff()

telio.stop()
telio.destroy()
```

```cs
using uniffi.libtelio;

var sk = GenerateSecretKey();
var adapter = GetDefaultAdapter();

Telio telio = new Telio(...);
telio.Start(sk, adapter);

var meshPk = GeneratePublicKey(sk);
// Register meshPk with api if needed
var jsonConfig = "<json config recieved from api>";
var config = DeserializeMeshnetConfig(jsonConfig);
// Change secret key if needed
telio.SetSecretKey(sk);
/* Turn on or update meshnet */
telio.SetMeshnet(config);
telio.SetMeshnetOff();

telio.Stop();
telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val sk = generateSecretKey()
val adapter = getDefaultAdapter()

val telio = Telio.new(...)!!
telio.start(sk, adapter)!!

val meshPk = generatePublicKey(sk)
// Register meshPk with api if needed
val jsonConfig = "<json config recieved from api>"
val config = deserializeMeshnetConfig(jsonConfig)!!
// Change secret key if needed
telio.setSecretKey(sk)!!
/* Turn on or update meshnet */
telio.setMeshnet(config)!!
telio.setMeshnet_off()!!

telio.stop()!!
telio.destroy()!!
```

</multi-code>

System network configuration:

Set tunnel interface address to `10.64.X.X/10` found in Mesh Map `ip_addresses\[0\]`.

DNS servers set to system defaults ( if needed via Telio Magic DNS forwarding).

Exclude all `derp_server.ipv4` from tunnel interface, bind it to default interface or use system protection methods.


### Magic DNS

Windows and Linux: App modifies native system.

Apple and Android: 
App enables/disables Telio Magic DNS proxy, forwarding desired DNS servers.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use telio::{ffi::*, types::*};

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let sk = generate_secret_key();
let adapter = get_default_adapter();

let telio = Telio::new(Default::default(), Box::new(EventHandler)).unwrap();
telio.start(sk, adapter).unwrap();

telio.enable_magic_dns(&[]).unwrap();
// Update if needed with new remote dns ip's
telio.enable_magic_dns(&["1.1.1.1".parse().unwrap()]).unwrap();
telio.disable_magic_dns().unwrap();

telio.stop().unwrap();
telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

sk := GenerateSecretKey()
adapter := GetDefaultAdapter()

telio, err := Telio {...}
_, err = telio.Start(sk, adapter)

_, err := telio.EnableMagicDns([]string)
// Update if needed with new remote dns ip's
dns_servers := [1]string{"1.1.1.1"}
_, err := telio.EnableMagicDns(dns_servers)
_, err := telio.DisableMagicDns()

_, err = telio.Stop()
_, err = telio.Destroy()
```

```swift
import libtelio

let sk = generateSecretKey()
let adapter = getDefaultAdapter()

let telio = Telio(...)
telio.start(sk, adapter)

telio.enableMagicDns([])
// Update if needed with new remote dns ip's
telio.enableMagicDns(["1.1.1.1"])
telio.disableMagicDns()

telio.stop()
telio.destroy()
```

```cs
using uniffi.libtelio;

var sk = GenerateSecretKey();
var adapter = GetDefaultAdapter();

Telio telio = new Telio(...);
telio.Start(sk, adapter);

telio.EnableMagicDns([]);
// Update if needed with new remote dns ip's
telio.EnableMagicDns(["1.1.1.1"]);
telio.DisableMagicDns();

telio.Stop();
telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val sk = generateSecretKey()
val adapter = getDefaultAdapter()

val telio = Telio.new(...)!!
telio.start(sk, adapter)!!

telio.enableMagicDns(emptyList())!!
// Update if needed with new remote dns ip's
telio.enableMagicDns(listOf("1.1.1.1"))!!
telio.disableMagicDns()!!

telio.stop()!!
telio.destroy()!!
```

</multi-code>

System network configuration:

Set real DNS server to `100.64.0.2`

If VPN node is enabled, force forward DNS servers (e.g. `1.1.1.1`) to go through tunnel. (Otherwise Nord DNS and CyberSec servers will not work!!!) 


### Meshnet + VPN
App enables meshnet, and connects to VPN Node.

System network configuration:

Set tunnel interface address to `10.64.X.X/10` found in Mesh Map `ip_addresses\[0\]`.

Route entire system traffic through tunnel interface.

Exclude all server_endpoint from tunnel interface, bind it to default interface or use system protection methods.

Exclude all derp_server.ipv4 from tunnel interface, bind it to default interface or use system protection methods.

DNS servers set to Nord DNS servers or CyberSec servers (if needed via Telio Magic DNS forwarding).


### Meshnet + Exit Node
App with enabled meshnet, connects to one of mesh map peer’s.

<multi-code-select></multi-code-select>

<multi-code>

```rust no_run
use std::str::FromStr;
use ipnetwork::IpNetwork;
use telio::{ffi::*, types::*};
use telio_crypto::PublicKey;

#[derive(Debug)]
struct EventHandler;
impl TelioEventCb for EventHandler {
    fn event(&self, payload: String) {}
}

let sk = generate_secret_key();
let adapter = get_default_adapter();

let telio = Telio::new(Default::default(), Box::new(EventHandler)).unwrap();
telio.start(sk, adapter).unwrap();

let mesh_map_node_public_key = PublicKey::from_str("QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=").unwrap();

telio.connect_to_exit_node(
    mesh_map_node_public_key,
    Some(vec![IpNetwork::from_str("0.0.0.0/0").unwrap()]),
    None
).unwrap();
telio.disconnect_from_exit_nodes().unwrap();

telio.stop().unwrap();
telio.destroy().unwrap();
```

```go
import github.com/nordsecurity/telio

sk := GenerateSecretKey()
adapter := GetDefaultAdapter()

telio, err := Telio {...}
_, err = telio.Start(sk, adapter)

allowedIps := [1]string{"0.0.0.0/0"}
_, err = telio.ConnectToExitNode(meshMapNodePublicKey, allowedIps, nil)
_, err = telio.DisconnectFromExitNodes()

_, err = telio.Stop()
_, err = telio.Destroy()
```

```swift
import libtelio

let sk = generateSecretKey()
let adapter = getDefaultAdapter()

let telio = Telio(...)
telio.start(sk, adapter)

telio.connectToExitNode(meshMapNodePublicKey, ["0.0.0.0/0"], nil)
telio.disconnectFromExitNodes()

telio.stop()
telio.destroy()
```

```cs
using uniffi.libtelio;

var sk = GenerateSecretKey();
var adapter = GetDefaultAdapter();

Telio telio = new Telio(...);
telio.Start(sk, adapter);

telio.ConnectToExitNode(meshMapNodePublicKey, ["0.0.0.0/0"], null);
telio.DisconnectFromExitNodes();

telio.Stop();
telio.Destroy();
```

```kotlin
import com.nordsec.libtelio.*

val sk = generateSecretKey()
val adapter = getDefaultAdapter()

val telio = Telio.new(...)!!
telio.start(sk, adapter)!!

telio.connectToExitNode(meshMapNodePublicKey, listOf("0.0.0.0/0"), null)!!
telio.disconnectFromExitNodes()!!

telio.stop()!!
telio.destroy()!!
```

</multi-code>

To change exit node disconnect and connect.
Using telio.connect_to_exit_node to connect to the exit node will give the exit node an auto-generated identifier. To manually set the identifier, use telio.connect_to_exit_node_with_id instead. The identifier is then given as the second argument, before the public key.

Set tunnel interface address to `10.64.X.X/10` found in Mesh Map `ip_addresses\[0\]`.

Route entire system traffic through tunnel interface.

Exclude all derp_server.ipv4 from tunnel interface, bind it to default interface or use system protection methods.

DNS servers set to default OS servers (if needed via Telio Magic DNS forwarding).


### Error handling
In an event, when telio crashes, and no event with panic message arrive, there’s a call `telio.get_last_error()` which returns last error message, that happened inside telio.
