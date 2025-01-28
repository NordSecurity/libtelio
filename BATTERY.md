# Intro
This document outlines guidelines for optimizing battery usage when using the libtelio library.
This document is mostly suited for mobile platforms since there the battery usage has the biggest impact.

Experiments show that data transmission (sending) consumes nearly as much battery as data reception on mobile devices.
Therefore, optimizations may have limited impact if only the device applies them, as the behavior of the
remote device also influences battery usage.

# Optimisations
## Increase keep-alive values
Keep-alive messages are sent to the peer/server to maintain the online status and preserve NAT mappings.
The higher the values, the better. Keep in mind:
- https://datatracker.ietf.org/doc/html/rfc4787#section-4.3 
"""
REQ-5:  A NAT UDP mapping timer MUST NOT expire in less than two
minutes, unless REQ-5a applies.
"""
- Keep-Alive packets are not acknowledged or retransmitted on failure
- WireGuard's **REKEY-AFTER-TIME** is 120s

Tip: best value according to known limitations is 61seconds, it's below minimal UDP mapping deadline
and also second packet happens at t=122s which is after **REKEY-AFTER-TIME** and WireGuard will then trigger
handshake attempts every 5seconds for the next **REKEY-ATTEMPT-TIME**(90s).

```
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

## DERP optimisations
### Disable keepalives for offline peers reported by DERP server

```
"derp":
{
    "enable_polling": true
}
```

### Increase DERP keepalives
This will have effect in rotating broken DERP connections to a different server
```
"derp":
{
    "tcp_keepalive": 60,
    "derp_keepalive": 60,
}
```

## Enable batching
Force keepalives to be batched together
```
"batching": {}
```

# What to look for
The less network activity, the better.

## Android
Battery Historian https://developer.android.com/topic/performance/power/setup-battery-historian
can be used to observe the radio state on Android devices.

## Other platforms
Observing any traffic activity towards and from the device can be done by doing packet capture
on the gateway or on the device itself.

