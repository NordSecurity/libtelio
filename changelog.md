### UNRELEASED
---
### Changelog
* LLT-3524: Replace [] operator with .get

<br>

### v4.0.3
### **Bruschetta**
---
* LLT-3113: Add upnp endpoint provider
* LLT-3634: `stun_plaintext_port` defaults to 0 when not provided in config
* LLT-3603: Add support for `allow_peer_send_files` to meshconfig
* LLT-3668: Stop Nurse before Derp
* LLT-3665: Fix missing forward zone after DNS zones clone
* LLT-3715: Fix incorrect send data length in derpcli manual mode
* LLT-3710: Fix infinite loop in STUN provider in case of nonet
* LLT-3506: Add ip field to node events

<br>

### v4.0.2
### **Bruschetta**
---
* LLT-3619: Update crypto box
* LLT-3636: Add derp server side keepalives configuration to feature config
* LLT-3654: Fix infinite loop in STUN endpoint provider when meshnet is off
* LLT-3619: Update crypto box
* LLT-3636: Add derp server side keepalives configuration to feature config
* LLT-3649: Remove slog mentions from README.md
* LLT-3654: Fix infinite loop in STUN endpoint provider when meshnet is off

<br>

### v4.0.1
### **Bruschetta**
---
### Changelog
* LLT-3423: Add identifier to `Node` and `ExitNode`, and telio function to supply an identifier when connecting to an exit node
* LLT-3404: Add github PR template
* LLT-3468: Separate Heartbeat collection from QoS so heartbeat collection can be alone enabled.
* LLT-3502: Refactor telio-nurse. Fix meshnet members list, conectivity matrix, external links data.
* LLT-3504: Enable nurse component. Its start has been accidentally removed during merges.
* LLT-3562: Add offline external nodes in analytics events.
* LLT-2948: Improve derpcli for large scale stress-testing
* LLT-3420: Box large futures
* NVA-3705: Configure Android SONAME
* LLT-3496: Fix is_exit flag when disconnecting from exit node
* LLT-3499: Fix missing libtelio tag version
* LLT-897: Enable sending self and member NAT type to moose
* LLT-3596: Do not fail to start whole meshnet if single peer config is invalid within meshmap
* LLT-3520: Add missing verification of sideload feature on macOS
* LLT-3477: Change absolute file path to module path in logger
* LLT-3472: Make feature `direct.providers` accept arbitrary strings with warning instead of error.
* Release build contains debug logs from now
* LLT-3616: Upgrade bindings for moose
* LLT-3647: Remove dependency on the outdated time crate
* LLT-3530: Log features at telio startup

<br>

### v4.0.0
### **Bruschetta**
---
### Changelog
* LLT-2732: Support direct connections for meshnet.
* LLT-3305: Skip firewall for VPN nodes
* LLT-3004: JNI FindClass calls from callbacks
* LLT-2968: Add contributor guidelines
* NVA-3645: Fix Nurse execution.
* LLT-3324: Fix magic dns being stuck for several seconds
* NVA-3634: Fix broken JNI_OnLoad binding
* LLT-3174: Allow apps to control PersistentKeepalive parameter of libtelio
* LLT-3340: Hide reflexive IPs from logs
* LLT-2893: Expose ffi version and tag
* Breaking changes 3.x -> 4.x:
  * Feature paths field is deprecated and has no influence in libtelio.
  * Feature "direct" was added egz:
    1. `{"direct": {}}`: Will enable all direct connection logic.
    2. `{"direct": { "providers": ["local", "stun"], "endpoint_interval_secs": 10 }`: equivalent to 1..
      Providers can be removed to limit nat traversal strategies, `endpoint_interval_secs` - specifies how often telio will try to look for endpoint changes.
  * Supported providers:
    * `local`: Retrieves endpoint by local interfaces
    * `stun`: Uses stun and wg-stun on derp servers to resolve public ip address for node.

  * Node's `endpoints` field was replaced by `endpoint` field reporting singular endpoint wireguard is actually using.
  * Node's `path_type` field now will either be `"relay"` or `"direct"`, vpn nodes `path_type` is always `"direct"`.
  * Communication between versions:
    * 4.x <-> 3.x can communicate only using `relay` path.
    * 3.x <-> 3.x can aditionaly communicate using `udp-hole-puch` path.
    * 4.x <-> 4.x can also communicate using `direct` path

<br>

### v3.4.2
### **Pastel de nata**
---
### Changelog
* Remove log_nat to avoid race in DerpRelay

<br>

### v3.4.1
### **Pastel de nata**
---
### Changelog
* LLT-3075: Fix moosevents bump.

<br>

### v3.4.0
### **Pastel de nata**
---
### Changelog
* LLT-909 Core: exit_dns feature - automatic dns forwarding through exit
* LLT-2892 MacOS: bind dns forward socket only when connected to vpn/exit
* LLT-2922: Log NAT type
* LLT-2890: QoS analytics (RTT, Throughput, Connection duration)
* LLT-2849: Telio as cargo usable lib
* LLT-3045: Add heartbeat interval field to analytics event
* LLT-3008: Stunner.fetch_endpoints should always at least return local endpoints

<br>

### v3.3.0
### **Chicken salad**
---
### Changelog
* LLT-131: Stateful firewall
* NVA-3180: Fix Android Java bindings on Rust versions at and above 1.61.
* LLT-2949: Add plaintext fallback to stunner.

<br>

### v3.2.1
### **Sauerkraut**
---
### Changelog
* LLT-2927: Bump tokio version to ">=1.22".

<br>

### v3.2.0
### **Sauerkraut**
---
### Changelog
* LLT-2908: Bump tokio version to ">=1.21.2".
* WVPN-4272: Windows: Add WireGuard-NT

<br>

### v3.1.8
### **Cheese Sticks**
---
### Changelog
* LLT-962: Add RTT analytics component in telio-nurse.
* LLT-2839: Populate moose device context info with data from nordvpnapp tracker.

<br>

### v3.1.7
### **Cheese Sticks**
---
### Changelog
* LLT-2836: Fix telio panic, while decrypting DERP. Fix `telio-router` connection reset.

<br>

### v3.1.6
### **Cheese Sticks**
---
### Changelog
* LLT-2754: DERPCLI: Add certificaton authority dangerous validation

<br>

### v3.1.5
### **Cheese Sticks**
---
### Changelog
* LLT-2754: DERPCLI: Add certification authority

<br>

### v3.1.4
### **Cheese Sticks**
---
### Changelog
* NVA-2888: Fix Android Java bindings.

<br>

### v3.1.3
### **Cheese Sticks**
---
### Changelog
* NVA-2875: Use libnduler ifaddrs implementation for Android
* LLT-2753: Removing panic from telio-task `Drop` in debug build.
* LLT-2760: Do not disconnect connected/unaffected nodes, when setting meshnet config.
* LLT-2334: Add checksum and port validation in MagicDNS.

<br>

### v3.1.2
### **Cheese Sticks**
---
### Changelog
* LLT-2696: Fixing windows socket binding during construction. Fixing socket's connect with timeout.

<br>

### v3.1.1
### **Cheese Sticks**
---
### Changelog
* NVA-2516: Stop libtelio tasks which are reported as unstopped
* LLT-2362: Relay config set fix
* LLT-1202: CMM responder test
* LLT-1368: Socket pool, protect udp_hole_punch
* NVA-2578: Skip unnecessary reconnect on network change notifications
* LLT-2319: Fix magic dns nxdomain responses
* LLT-2271: implementing ping and metrics mechanism on `udp_hole_punch`
* LLT-2391: `Stunner` call rate reduced to 1 call/min
* LLT-2159: fix `udp_hole_punch` route flicker, by introducing persistent pings on path level
* LLT-2498: introducing connection upgrade timeout on `telio-router`
* LLT-200, WVPN-4418: Improved handling of bindings exports

<br>

### v3.1.0
### **Cheese Sticks**
---
### Changelog
* LLT-862: Nat Traversal.
* LLT-1719: Dynamic configuration.
* LLT-1339: Path change events.
* LLT-1278: UHP Unit tests.

<br>

### v3.0.4
### **Protein Philadelphia**
---
### Changelog
* LLT-1963: Core: Fix nurse stop
* LLT-2252: Fix FFI constructor returning null inappropriately
* LLT-1338: Natlab: Add udp blocking gw

<br>

### v3.0.3
### **Protein Philadelphia**
---
### Changelog
* LLT-1505: CI: Add `glass` utility for managing Docker images
* LLT-1448: CORE: Revert 25s keepalive for android/ios
* LLT-1664: Fix nat-lab `./run_local.py` error
* LLT-1702: Share binary files via /libtelio volume
* LLT-1166: Migrate Natlab python utilities to `ci-helper-scripts` repo
* LLT-1759: Pin natlab wireguard go version
* LLT-1981: Core: Fix "server list exhausted" errors
* LLT-1344: Core: Fix ffi crashing on telio constructor

<br>

### v3.0.2
### **Protein Philadelphia**
---
### Changelog
* LLT-1372: Paralelize client creation
* LLT-1373: Expose derpcli client stats via http
* LLT-1412: Natlab: remove unused pip dependency
* LLT-1137: Core: Generate meshnet ID
* LLT-1221: Reuse test coverage reporting from ci-helper-scripts
* LLT-1065: CI: reuse build script utilities from ci-helper-scripts
* LLT-1537: Fix local builds not working
* LLT-1447: Core: Fix meshnet disconnect/reconnect

<br>

### v3.0.1
### **Protein Philadelphia**
---
### Changelog
* LLT-1135: Add stunner integrational tests
* LLT-1097 Ensure that all messages transmitted over DERP relay are encrypted
* WVPN 3869: Return specific error for telio library when adapter is already started
* LLT-1028 Core: Fix double keepalive on session init for BoringTun
* WVPN 3869 (2): Updated interface files to reflect the new status
* LLT-832 Core: Add Lana feature
* LLT-1128 Windows: Enable MagicDNS
* LLT-1333 CI: Fix Pages job
* LLT-1201 CI: Added lint to warn about mpsc send() usages
* LLT-1225 Core: add `Stunner` component to `telio-route`
* LLT-1136: Add pinger integrational tests
* LLT-1393: Update libtelio documentation

<br>

### v3.0.0
### **Protein Philadelphia**
---
### Changelog
* LLT-1173 Derpcli: Update derpcli with stress testing mode
* LLT-1257 Core: Extend`telio_new` with`feature_config`

<br>
