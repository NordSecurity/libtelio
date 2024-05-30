from telio_features import TelioFeatures, Direct, Lana, Nurse, Qos, ExitDns, Dns


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
        )
    )
    expected_nurse_qos = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "nurse": {"fingerprint": "fingerprint", "qos": {"rtt_interval": 5, "rtt_tries": 3, "rtt_types": ["Ping"], "buckets": 5}, "heartbeat_interval": 3600, "initial_heartbeat_interval": 10, "enable_nat_type_collection": false, "enable_relay_conn_data": false}}"""
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
    )
    expected_full = TelioFeatures.from_json(
        """{"is_test_env": false, "exit_dns": {"auto_switch_dns_ips": true}, "direct": {"providers": ["stun", "local"]}, "lana": {"prod": false, "event_path": "/"}, "nurse": {"fingerprint": "alpha", "qos": {"rtt_interval": 5, "rtt_tries": 3, "rtt_types": ["Ping"], "buckets": 5}, "heartbeat_interval": 3600, "initial_heartbeat_interval": 10, "enable_nat_type_collection": true, "enable_relay_conn_data": true}}"""
    )
    assert full_features == expected_full
    assert full_features.to_json() == expected_full.to_json()

    multicast_features = TelioFeatures(multicast=False)
    expected_multicast = TelioFeatures.from_json(
        """{"is_test_env": true, "exit_dns": {"auto_switch_dns_ips": true}, "multicast":false}"""
    )
    assert multicast_features == expected_multicast
    assert multicast_features.to_json() == expected_multicast.to_json()
