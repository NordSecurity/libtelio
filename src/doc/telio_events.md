# Documentation For Describing Telio Events

This module documents the events reported by the Telio library.

## Telio Error Event

[Error][telio_model::event::Error] events are reported in the following format:

```json
{
  "type": "error",
  "body": {
    "level": "<critical|severe|warning|notice>",
    "code": "<noerror|unknown>",
    "msg": string?
  }
}
```

Fields:

- level - error severity:

    - critical - telio panicked
    - severe - telio can continue operating, but parts of it can malfunction
    - warning - warning that things can get wrong
    - notice - not a critical error

- code - common error code:

    - noerror - default value, not an error.
    - unknown - unknown error

- msg - custom error string, can be empty


### When error event is reported?

[Error][telio_model::event::Error] events are reported when a panic occurs on telio side after registering for Telio events by calling `telio_new`.

### Handling error events

- level:

    - critical -  telio panicked, so it must be restarted calling telio_destroy_hard() and starting init procedure from scratch (invoking telio_new() or similar path). Note, that destroying and re-creating telio should not be pe3rformed while handling incoming event (not on telio thread’s context).

## Telio Node Event

[Node][telio_model::mesh::Node] events are reported in the following format:

```json
{
  "type": "node",
  "body": {
    "identifier": "<Node UUID>",
    "public_key": "<base64 key>",
    "state": "<disconnected|connecting|connected>",
    "link_state": "<null|down|up>"
    "is_exit": bool,
    "is_vpn": bool,
    "ip_addresses": [ "meshnet ip" ] // VPN nodes have reserved addresses: ["10.5.0.1", "100.64.0.1"]
    "allowed_ips": [ "<CIDR>" ],
    "endpoint":"<ip:port>",
    "hostname":"<Node hostname>",
    "path": "<direct|relay>",
  }
}
```

Fields:

- identifier - A node identifier passed via meshmap, when event is concerning meshnet nodes, and identifier passed via connect_to_exit_node_with_id(...) when connecting to VPN node or null otherwise.

- public_key - Node public key in base64 form. Can be used as identifier.

- state - Connection state of node:

    - disconnected -  Node is not connected and there will be no attempt to connect to it
    - connecting - Node is not connected, but libtelio is actively trying to connect to it
    - connected - Node is connected

- link_state - Link state hint (For additional info check RFC-LLT-0045)

    - null - If it’s null or missing it means that the no-link detection mechanism is disabled
    - down - Link state is down reported as down if the state is different from connected or if there the no-link detection mechanism has detected that the link might be down
    - up - Reported only if the node is connected and there are no clear indications that the link may be down

- is_exit - It is expected that all traffic will be redirected to this node (true if exit node or VPN node)

- is_vpn - Node represents VPN server (true if VPN node only)

- ip_addresses - Address(es) assigned to a node.

- allowed_ips - Indicates subnets being routed to this node.

- hostname - DNS name of a node.

- path - Indicates whether the connection is direct or relay’ed.

- endpoint - The IP address which is used for underlying communication with the node. May be localhost, which indicates relayed connection.

### When node event is reported?

Node events are reported by any change to any property of the node (be it a VPN node or a mesh node) after registering for Telio events by calling `telio_new`.

### Common scenarios:

- VPN flow (node is not in meshnet config, identified by `public_key`):

    - Connection to VPN server is `requestconnect_to_exit_node(...)` called→ `{ "state": "connecting", "is_vpn": true, "is_exit": true, ... }`
    - Connection to VPN server is established → `{ "state": "connected", ... }`
    - Connection to VPN server is lost → `{ "state": "connecting", ... }`
    - Disconnection requested by calling `disconnect_from_exit_node[s](...)` → `{ "state": "disconnected", ... }`

- MESH flow (node is in meshnet config):

    - Enable meshnet by calling `set_meshnet(...)` -> `{ "state": "connecting", "is_vpn": false, "is_exit": false, ...}`
    - Meshnet node connection established → `{ "state": "connected", ... }`
    - Meshnet node connection lost → `{ "state": "connecting", ... }`
    - Node is promoted to be an exit node by calling `connect_to_exit_node(...)` → `{ "is_exit": true, ... }`
    - Node is demoted to be meshnet node by calling `disconnect_from_exit_node[s](...)` → `{ "is_exit": false, ... }`
    - Meshnet disabled by calling `set_meshnet_off(...)` → `{ "state": "disconnected", ... }`

## Telio Relay Event

[Relay][telio_model::config::Server] events contain the Derp Server configuration in JSON and are reported in the following format:

```json
{
  "region_code": string,
  "name": string,
  "hostname": string,
  "ipv4": string,
  "relay_port": int,
  "stun_port": int,
  "stun_plaintext_port": int,
  "public_key": string,
  "weight": int,
  "use_plain_text": bool,
  "conn_state": "<disconnected|connecting|connected>"
}
```

### When node event is reported?

A [Relay][telio_model::config::Server] event is reported every time the relay configuration changes or we start connecting to a different relay server.
