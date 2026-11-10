# Tests for the consumed-builder guard in _patch_builder (serialization.py).
# Discarding a setter's return value and calling further methods must raise,
# preventing silent omission of steps from the _call_log during Pyro5 replay.
import pytest
import tests.uniffi.telio_bindings as libtelio
from tests.uniffi.serialization import init_serialization
from tests.uniffi.telio_bindings import (
    VpnConnectionConfigBuilder,
    MeshnetConnectionConfigBuilder,
)

# Call directly so tests run without Docker / TELIO_BIN_PROFILE.
init_serialization(libtelio)

PUBLIC_KEY = "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo="
ENDPOINT = "1.2.3.4:51820"

# -- Error cases: discarded return values ------------------------------------


def test_vpn_discard_force_pq_then_build_raises():
    builder = VpnConnectionConfigBuilder(PUBLIC_KEY, ENDPOINT)
    builder.force_pq()
    with pytest.raises(RuntimeError, match="consumed builder"):
        builder.build()


def test_vpn_discard_setter_then_next_setter_raises():
    builder = VpnConnectionConfigBuilder(PUBLIC_KEY, ENDPOINT)
    builder.with_identifier("lost")
    with pytest.raises(RuntimeError, match="consumed builder"):
        builder.force_pq()


def test_meshnet_discard_setter_then_build_raises():
    builder = MeshnetConnectionConfigBuilder(PUBLIC_KEY)
    builder.with_allowed_ips([])
    with pytest.raises(RuntimeError, match="consumed builder"):
        builder.build()


# -- Happy-path: correct chaining must not raise -----------------------------


def test_vpn_inline_chain_succeeds():
    config = (
        VpnConnectionConfigBuilder(PUBLIC_KEY, ENDPOINT)
        .with_identifier("natlab")
        .force_pq()
        .build()
    )
    assert config is not None


def test_vpn_pq_chain_from_vpn_py_pattern_succeeds():
    pq = True
    builder = VpnConnectionConfigBuilder(PUBLIC_KEY, ENDPOINT)
    if pq:
        builder = builder.with_identifier("natlabpq").force_pq()
    else:
        builder = builder.with_identifier("natlab")
    config = builder.build()
    assert config is not None


# -- _call_log completeness --------------------------------------------------


def test_vpn_call_log_contains_all_chained_methods():
    config = (
        VpnConnectionConfigBuilder(PUBLIC_KEY, ENDPOINT)
        .with_identifier("test-node")
        .force_pq()
        .build()
    )
    method_names = [entry[0] for entry in config._call_log]  # type: ignore[attr-defined]  # pylint: disable=protected-access,no-member
    assert method_names == [
        "VpnConnectionConfigBuilder",
        "with_identifier",
        "force_pq",
        "build",
    ]
