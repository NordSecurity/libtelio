from telio_features import (
    Firewall,
    TelioFeatures,
    Direct,
    Lana,
    LinkDetection,
    Nurse,
    Qos,
    ExitDns,
    Dns,
)


def test_telio_features():
    default_features = TelioFeatures()
    expected_default = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}}"""
    )
    assert default_features == expected_default
    assert default_features.to_json() == expected_default.to_json()

    direct_features = TelioFeatures(direct=Direct(providers=["stun", "local"]))
    expected_direct = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true},
        "direct": {"providers": ["stun", "local"]}}"""
    )
    assert direct_features == expected_direct
    assert direct_features.to_json() == direct_features.to_json()

    lana_features = TelioFeatures(lana=Lana(prod=True, event_path="/"))
    expected_lana = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "lana": {"prod": true, "event_path": "/"}}"""
    )
    assert lana_features == expected_lana
    assert lana_features.to_json() == expected_lana.to_json()

    nurse_features = TelioFeatures(nurse=Nurse(fingerprint="fingerprint"))
    expected_nurse = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "nurse": {"fingerprint": "fingerprint"}}"""
    )
    assert nurse_features == expected_nurse
    assert nurse_features.to_json() == expected_nurse.to_json()

    nurse_qos_features = TelioFeatures(
        nurse=Nurse(
            fingerprint="fingerprint",
            qos=Qos(rtt_interval=5, rtt_tries=3, rtt_types=["Ping"], buckets=5),
            heartbeat_interval=3600,
            initial_heartbeat_interval=10,
            enable_relay_conn_data=False,
            enable_nat_type_collection=False,
            state_duration_cap=123,
        )
    )
    expected_nurse_qos = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "nurse": {"fingerprint": "fingerprint", "qos": {"rtt_interval": 5, "rtt_tries": 3, "rtt_types": ["Ping"], "buckets": 5}, "heartbeat_interval": 3600, "initial_heartbeat_interval": 10, "enable_nat_type_collection": false, "enable_relay_conn_data": false, "state_duration_cap": 123}}"""
    )
    assert nurse_qos_features == expected_nurse_qos
    assert nurse_qos_features.to_json() == expected_nurse_qos.to_json()

    full_features = TelioFeatures(
        is_test_env=False,
        direct=Direct(providers=["stun", "local"]),
        lana=Lana(prod=False, event_path="/"),
        nurse=Nurse(
            fingerprint="alpha",
            qos=Qos(rtt_interval=5, rtt_tries=3, rtt_types=["Ping"], buckets=5),
            heartbeat_interval=3600,
            initial_heartbeat_interval=10,
            enable_relay_conn_data=True,
            enable_nat_type_collection=True,
        ),
        dns=Dns(
            exit_dns=ExitDns(auto_switch_dns_ips=True),
            ttl_value=60,
        ),
        link_detection=LinkDetection(
            rtt_seconds=10, no_of_pings=1, use_for_downgrade=True
        ),
    )
    expected_full = TelioFeatures.from_json(
        """{"is_test_env": false, "exit_dns": {"auto_switch_dns_ips": true}, "direct": {"providers": ["stun", "local"]}, "lana": {"prod": false, "event_path": "/"}, "nurse": {"fingerprint": "alpha", "qos": {"rtt_interval": 5, "rtt_tries": 3, "rtt_types": ["Ping"], "buckets": 5}, "heartbeat_interval": 3600, "initial_heartbeat_interval": 10, "enable_nat_type_collection": true, "enable_relay_conn_data": true}, "link_detection": {"rtt_seconds": 10, "no_of_pings": 1, "use_for_downgrade": true}}"""
    )
    assert full_features == expected_full
    assert full_features.to_json() == expected_full.to_json()

    multicast_features = TelioFeatures(multicast=False)
    expected_multicast = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "multicast":false}"""
    )
    assert multicast_features == expected_multicast
    assert multicast_features.to_json() == expected_multicast.to_json()

    firewall_features = TelioFeatures(firewall=Firewall(boringtun_reset_conns=False))
    expected_firewall = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "firewall": {"boringtun_reset_conns": false}}"""
    )
    assert firewall_features == expected_firewall
    assert firewall_features.to_json() == expected_firewall.to_json()

    link_detection_features = TelioFeatures(
        link_detection=LinkDetection(
            rtt_seconds=10, no_of_pings=1, use_for_downgrade=False
        )
    )
    expected_link_detection = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "link_detection": {"rtt_seconds": 10, "no_of_pings": 1, "use_for_downgrade": false}}"""
    )
    assert link_detection_features == expected_link_detection
    assert link_detection_features.to_json() == expected_link_detection.to_json()
