<!-- Note: this file is auto-generated. See CONTRIBUTING.md for details. -->

### v5.0.0-rc
### **Chicken Salad**
---
* LLT-5145: Add init_cert_store method to FFI layer (only relevant for integrating on android)
* LLT-4351: Fix when shutting down meshnet, in the disconnect event, path is sometimes incorrectly reported as direct
* LLT-2515: Implement PMTU discovery for VPN connection paths on Linux/Android
* LLT-5141: Add section about feature config to integration docs
* LLT-5033: LibtelioSwift uses dylibs instead of static libraries
* LLT-5038: Add doc rs as in-repo documentation system skeleton
* LLT-4873: Remove old SWIG FFI bindings
* LLT-5036: Remove unused dependency features
* LLT-5039: Make connection reporting unaffected by system time changes
* LLT-4954: Handle system sleep/wakeup in nat/derp monitoring
* LLT-4856: Enable aggregator timed events
* LLT-5139: Change the interval missed tick behaviour to Delay in RepeatedActions::add_action
* LLT-4996: nurse: Stop adding virtual peers to qos
* LLT-4154: Optimize Upnp/Stun providers
* LLT-4168: Fix telio-dns assert panics in debug mode
* LLT-5034: Upgrade rust toolchain to v1.77.2
* LLT-4924: Enable size reduction compiler flags
* LLT-3474: Add bindings to windows and android artifacts
* LLT-5102: Add integration docs to rustdoc
* LLT-5088: Update moose to v5.0.0-libtelioApp
* LLT-5140: Change FeatureNurse and FeatureQoS to use u64 instead of duration
* LLT-4981: Add upgrade decision message
* LLT-4858: NAT state analytics reporting

<br>

### v4.3.2
### **Bravas**
---
* LLT-5078: Fix telio-proxy panic

<br>

### v4.3.1
### **Bravas**
---
* LLT-5068: Bump MOOSE to v4.0.1

<br>

### v4.3.0
### **Bravas**
---

New tracker confirmed stable

<br>

### v4.3.0-rc1
### **Bravas**
---
* LLT-5004: Wireguard go oscillation
* LLT-4983: Expose telio_generate_stack_panic method
* LLT-1113: Add no-link detection mechanism
* LLT-5007: Bump moose tracker to v3.0.0-libtelioApp
* LLT-4509: Enable windows arm64 build.
* LLT-5009: Enable QoS feature by default
* LLT-4980: Add exponential backoff for socket updates on error

<br>

### v4.3.0-rc0
### **Bravas**
---
* LLT-4915: Update the moose tracker to v1.0.0-libtelioApp
* LLT-4978: Bump moose tracker to v2.0.0-libtelioApp
* LLT-4970: PQ VPN is enabled by calling `telio_connect_to_exit_node_postquantum()`
* LLT-5002: Fix preshared key parsing logic

<br>

### v4.2.8
### **Space-cakes**
---
* LLT-4644: Fix wintun adapter creation

<br>

### v4.2.7
### **Space-cakes**
---
* LLT-5078: Fix telio-proxy panic

<br>

### v4.2.6
### **Space-cakes**
---
* LLT-5002: Fix preshared key parsing logic
* LLT-5004: Wireguard go oscillation
* LLT-1113: Add no-link detection mechanism
* LLT-4983: Expose telio_generate_stack_panic method
* LLT-4509: Enable windows arm64 build.
* LLT-5007: Bump moose tracker to v3.0.0-libtelioApp
* LLT-5009: Enable QoS feature by default
* LLT-4980: Add exponential backoff for socket updates on error

<br>

### v4.2.5
### **Space-cakes**
---
* LLT-4908: Lowered DNS TTL time for nicknames and NXDomain responses
* LLT-4916: Allow any case nicknames
* LLT-4948: Change missed tick behavior from burst to delay
* LLT-4967: Clear leftover STUN peer after meshnet is turned off
* LLT-4913: Skip qos analytics ping for unconnected peers
* LLT-4968: Make the default nurse initial_heartbeat_interval to be 5 minutes
* LLT-4850: Add missing VPN meshnet address to analytics
* LLT-4917: Fix the issue with wireguard-go failing to bind to a port on some devices
* LLT-4870: Bring back PQ
* LLT-4406: Implement error handling for proxy egress
* LLT-4980: Introduce synchronization for the endpoint map in telio-proxy

<br>

### v4.2.4
### **Space-cakes**
---
* LLT-4878: Fix FFI layer which forbids NULL for `telio_connect_to_exit_node()` calls

<br>

### v4.2.3
### **Space-cakes**
---
* LLT-4869: Fix maven upload
* LLT-4870: Revert post quantum

<br>

### v4.2.2
### **Space-cakes**
----
* LLT-4662: Update rustix dependency
* LLT-4667: Fix panic in boringtun
* LLT-4663: Update zerocopy dependency
* LLT-4543: Log ffi calls
* LLT-4310: Change stun client/server to the one, which supports IPv6
* LLT-4381: Use OS certificates instead of hardcoded mozilla list
* LLT-4667: Fix libtelio panicking on linux + boringtun
* LLT-4633: Bind to interfaces which has router property only on apple
* LLT-4688: Add detailed logs on boringtun socket failures
* LLT-4598: Introduce IPv6 -> IPv4 fallback in WG-STUN
* LLT-4698: Fix exp. backoff in WG-STUN
* LLT-4490: Ensure that meshnet entities are started only when meshnet is started
* LLT-4335: Make blocking upnp gw search async
* LLT-4620: Implement the post quantum key rotation mechanism
* LLT-4616: Make nurse qos ping asynchronous
* LLT-4652: Bump boringtun version to v1.1.10
* LLT-4557: Document functions from helpers.py
* LLT-4661: Update wireguard-go and related Go dependencies
* LLT-4528: Mute peers in proxy when upgrading to direct connection
* LLT-4729: Fix maven upload
* LLT-4562: Dont notify socket waiter in MacOS during cleanup

<br>

### v4.2.1
### **Space-cakes**
----
* LLT-4006: Restrict nat-lab containers capabilities
* LLT-4586: Fix wireguard-go initialization crash
* LLT-4634: Add wildcarded domains to DNS records
* LLT-4225: Migrate Telio to use the tracing crate instead of log crate
* LLT-4594: Fix session keeper's bug, to enable ICMP6 packets
* LLT-4597: Fix QoS' IPv6 pinging
* LLT-4614: Implement the post quantum VPN handshake

<br>

### v4.2.0
### **Space-cakes**
---
* LLT-4008: Add support for AAAA records in telio-dns
* LLT-4012: Fix firewall being stuck on LAST_ACK after FIN
* LLT-4023: Add validation that meshnet and device keys match
* LLT-4056: Add git commit requirements
* LLT-3948: Add IPv6 functionality and fallback to session_keeper module
* LLT-3629: Add IPv6 support to nat-lab
* LLT-3913: Deduplicate IPs of external wireguard peers
* LLT-3869: Turn off relayed traffic to offline peers
* LLT-3775: Add test for lana validators
* LLT-4050: Add support for IPv6 packet handling in telio-dns
* LLT-3875: Don't reconnect to Derp when Multiplexer channel is closed.
* LLT-4128: Add integration tests for IPv6 MagicDNS service
* LLT-3316: Improve usage of peer-reflexive endpoints
* LLT-4246: Add self nordname as well as self IP address to the DNS records
* LLT-4136: Migrate Natlab VMs to use libvirt
* LLT-4159: Clarify purpose of hardcoded secrets in repo
* LLT-3451: Use workspace dependencies
* LLT-3628: Enable IPv6 and add tests for it (unit and nat-lab).
* LLT-4042: IPv6 firewall nat-lab tests.
* LLT-4013: Add conntrack rules for icmp
* LLT-4152: Suspend SessionKeeper and CrossPingCheck for unresponsive peers
* LLT-4286: Add icmp error packet handling to firewall
* LLT-3951: IPv6 analytics.
* LLT-4409: Wait for listen port only if meshnet is enabled
* LLT-4375: Add meshmap config support for custom peer names
* LLT-4376: Add magicdns support for two dns bindings
* LLT-3923: Change DERP and STUN identifiers
* LLT-4202: Do not answer DNS request if forward lookup fails
* LLT-4427: Fix issue with malformed disconnect event
* LLT-4280: Implement TCP and UDP connection reset upon VPN server change for boringtun adapter
* LLT-4124: Add IPv6 feature flag
* LLT-3950: Enable IPv6 for wg-stun.
* LLT-4502: Implement ICMP, UDP and TCP conntrack tracking for each peer separately
* LLT-4508: Fetch windows dependencies from local gitlab registry
* LLT-4552: Add way to flush events when stopping
* LLT-4583: Don't add IPv6 addresses to wireguard when IPv6 feature is disabled
* LLT-4613: Fix boringtun performs spurious rekeying

<br>

### v4.1.3
---
* LLT-4515: Add nordvpn app version to moose context

<br>

### v4.1.2
---
* LLT-4432: Use forked system-configuration crate to prevent iOS linking errors
* LLT-4433: Bump moose version to v0.8.2

<br>

### v4.1.1
---
* LLT-3777: Apply rebinding logic to all Apple platforms

<br>

### v4.1.0
---
* LLT-3914: Add apple tvOS support
* LLT-4360: Bump rust version to 1.72

<br>

### v4.0.9
---
* LLT-4179: Fix issue where first WG-STUN request would fail due to missing WG-STUN peer
* LLT-4233: Add moose init callback validation
* LLT-4266: Add exit node clearing when disabling meshnet
* LLT-4306: Prevent infinite loop in STUN handler on socket error

<br>

### v4.0.8
---
* LLT-3990: Add initial heartbeat interval to feature config
* LLT-4166: Bump tokio-rustls version
* LLT-4204: Add `meshnet_enabled` field

<br>

### v4.0.7
---
* LLT-4119: Fix multiple bugs in telio-firewall. Mainly whitelist vpn server
* LLT-4002: Review log-levels of spammy log messages

<br>

### v4.0.6
---

<br>

### v4.0.5
---
* LLT-3832: Upgrade python cryptography to 41.0.1
* LLT-3855: Add "release.py" helper script, for easier release preparation
* LLT-3813: Update trust-dns to 0.22.1
* LLT-3901: Don't log warn for optional analytics fix.
* LLT-3878: Reduce "cross_ping_check" log output
* LLT-3791: Remove telio-wg as telio-model dependency
* LLT-3010: Fix telio unit-tests
* LLT-3651: Integration test for NAT type
* LLT-3943: Fix secret key clamping issue causing instabilities.
* LLT-3909: Fix stun poll intervals on happy path
* LLT-3849: Fix and adjust test for `telio-task` drop
* LLT-3592: Bind Ipv6 sockets on macOs
* LLT-3626: Implement IPv6 support in telio-firewall

<br>

### v4.0.4
### **Bruschetta**
---
* LLT-3524: Replace [] operator with .get
* LLT-3554: Add version in FileInfo for windows binary.
* LLT-3764: Upgrade moose to 0.6.0
* LLT-3740: Add endpoint gone notification for endpoint providers
* LLT-3754: Fix Android getifaddrs permission error
* LLT-3506: Add ip field to node events
* LLT-3638: Store fingerprints persistently
* LLT-3771: Fix derp server list loop
* LLT-3497: Don't bind ICMP session_keeper socket on Android
* LLT-3772: Fix derp infinite loop

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
