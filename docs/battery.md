
# Libtelio battery opimizations

## Intro

This document outlines guidelines for optimizing battery usage when using the libtelio library.

Experiments indicate that data transmission (sending) consumes nearly as much battery as data reception on mobile devices.
Therefore, optimizations may have limited impact if only the device applies them, as the behavior of the
remote device also influences battery usage.

## Suggestions

### Increase keep-alive values

Keep-alive messages are sent to the peer/server to maintain the online status and preserve NAT mappings for direct connections.
The higher the keepalive values, the better in terms of battery usage.
Tip: The optimal keep-alive interval is 61 seconds, based on the following considerations:

- It is below the minimum NAT UDP mapping timeout of 120 seconds (RFC 4787, Section 4.3).
- If the first packet is lost, the second packet is sent at 122 seconds, which is after WireGuard's **REKEY-AFTER-TIME** (120 seconds)
which will trigger handshake attempts every 5 seconds for **REKEY-ATTEMPT-TIME** (90 seconds).

```json
"wireguard":
{
    "persistent_keepalive": {
        "vpn": 61,
        "stun": 61,
        "direct": 61,
        "proxying": 61
    }
}
```

**Note**: Libtelio considers `3 x persistent_keepalive.direct` seconds timeout for receiving data from the peer before downgrading.
Long interval will cause downgrades to be delayed, consider using `link_detection` feature together:

```json
"link_detection": {
    "use_for_downgrade": true,
}
```

### DERP optimisations

#### Disable keepalives for offline peers reported by DERP server

```json
"derp":
{
    "enable_polling": true
}
```

#### Increase DERP keepalives

```json
"derp":
{
    "tcp_keepalive": 60,
    "derp_keepalive": 60,
}
```

### Android

[Battery Historian](https://developer.android.com/topic/performance/power/setup-battery-historian)
can be used to observe the radio state on Android devices.

### Other platforms

Observing any traffic activity towards and from the device can be done by doing packet capture
on the gateway or on the device itself.
