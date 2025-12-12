from tests.uniffi import (
    FeatureFirewall,
    FeaturesDefaultsBuilder,
    FirewallBlacklistTuple,
    IpProtocol,
    deserialize_feature_config,
)


def test_telio_features_builder_empty():
    built = FeaturesDefaultsBuilder().build()
    json = """
    {
        "lana": null,
        "nurse": null,
        "direct": null,
        "derp": null,
        "link_detection": null,
        "flush_events_on_stop_timeout_seconds": null,
        "multicast": false,
        "ipv6": false,
        "nicknames": false
    }
    """
    expect = deserialize_feature_config(json)

    assert expect == built


def test_telio_features_builder_firewall():
    built = FeaturesDefaultsBuilder().build()

    built.firewall = FeatureFirewall(
        neptun_reset_conns=False,
        boringtun_reset_conns=False,
        exclude_private_ip_range="1.2.3.4/10",
        outgoing_blacklist=[
            FirewallBlacklistTuple(protocol=IpProtocol.UDP, ip="8.8.4.4", port=30)
        ],
    )

    json = """
    {
        "lana": null,
        "nurse": null,
        "firewall": {
            "exclude_private_ip_range": "1.2.3.4/10",
            "outgoing_blacklist": [{
                    "protocol": "UDP",
                    "ip": "8.8.4.4",
                    "port": 30
            }],
            "neptun_reset_conns": false
        },
        "direct": null,
        "derp": null,
        "link_detection": null,
        "flush_events_on_stop_timeout_seconds": null,
        "multicast": false,
        "ipv6": false,
        "nicknames": false
    }
    """
    expect = deserialize_feature_config(json)

    assert expect == built


def test_telio_features_builder_lana():
    built = FeaturesDefaultsBuilder().enable_lana("some/path", False).build()
    json = """
    {
        "lana": {
            "event_path": "some/path",
            "prod": false
        },
        "nurse": null,
        "direct": null,
        "derp": null,
        "link_detection": null,
        "flush_events_on_stop_timeout_seconds": null,
        "multicast": false,
        "ipv6": false,
        "nicknames": false
    }
    """
    expect = deserialize_feature_config(json)

    assert expect == built


def test_telio_features_builder_all_defaults():
    built = (
        FeaturesDefaultsBuilder()
        .enable_nurse()
        .enable_direct()
        .enable_battery_saving_defaults()
        .enable_link_detection()
        .enable_flush_events_on_stop_timeout_seconds()
        .enable_multicast()
        .enable_ipv6()
        .enable_nicknames()
        .enable_batching()
        .build()
    )
    json = """
    {
        "lana": null,
        "wireguard": {
            "persistent_keepalive": {
                "vpn": 115,
                "direct": 10,
                "proxying": 125,
                "stun": 125
            }
        },
        "derp": {
            "enable_polling": true,
            "tcp_keepalive": 125,
            "derp_keepalive": 125
        },
        "nurse": {},
        "direct": {},
        "link_detection": {},
        "flush_events_on_stop_timeout_seconds": 0,
        "multicast": true,
        "ipv6": true,
        "nicknames": true,
        "batching": {
            "direct_connection_threshold": 0
        }
    }
    """
    expect = deserialize_feature_config(json)

    assert expect == built, f"json:\n{expect}\n\nbuilt:\n{built}"
