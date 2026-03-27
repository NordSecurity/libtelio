"""Pytest fixtures wrapping helpers.setup_environment / setup_connections."""

from __future__ import annotations

import asyncio
import pytest
import pytest_asyncio
from contextlib import AsyncExitStack
from tests.helpers import (
    SetupParameters,
    setup_connections as _setup_connections,
    setup_environment as _setup_environment,
    setup_mesh_nodes as _setup_mesh_nodes,
    Environment,
)
from tests.helpers_vpn import VpnConfig
from tests.mesh_api import API
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import ConnectionManager
from typing import AsyncGenerator, Callable, Awaitable, List, Optional, Union, Tuple


# ---------------------------------------------------------------------------
# 1) Shared AsyncExitStack
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(name="exit_stack")
async def _exit_stack() -> AsyncGenerator[AsyncExitStack, None]:
    """Provide an AsyncExitStack whose lifetime spans the entire test."""
    stack = AsyncExitStack()
    yield stack
    try:
        await asyncio.wait_for(stack.aclose(), timeout=60)
    except asyncio.TimeoutError:
        raise RuntimeError(
            "exit_stack fixture teardown timed out after 60s — "
            "likely a context manager is stuck during cleanup"
        ) from None


# ---------------------------------------------------------------------------
# 2) Factory fixture for setup_connections
# ---------------------------------------------------------------------------
@pytest.fixture(name="setup_connections_factory")
def _setup_connections_factory(
    exit_stack: AsyncExitStack,
) -> Callable[..., Awaitable[List[ConnectionManager]]]:
    """Return a callable that forwards to helpers.setup_connections
    using the shared *exit_stack*.

    Usage inside a test or another fixture::

        managers = await setup_connections_factory([ConnectionTag.DOCKER_VPN_1])
    """

    async def _factory(
        connection_parameters: List[
            Union[
                ConnectionTag,
                Tuple[ConnectionTag, Optional[list]],
            ]
        ],
    ) -> List[ConnectionManager]:
        return await _setup_connections(exit_stack, connection_parameters)

    return _factory


# ---------------------------------------------------------------------------
# 2b) Factory fixture for setup_mesh_nodes
# ---------------------------------------------------------------------------
@pytest.fixture(name="setup_mesh_nodes_factory")
def _setup_mesh_nodes_factory(
    exit_stack: AsyncExitStack,
) -> Callable[..., Awaitable[Environment]]:
    """Return a callable that forwards to helpers.setup_mesh_nodes
    using the shared *exit_stack*."""

    async def _factory(
        instances: List[SetupParameters],
        is_timeout_expected: bool = False,
        provided_api=None,
        vpn=None,
    ) -> Environment:
        return await _setup_mesh_nodes(
            exit_stack,
            instances,
            is_timeout_expected=is_timeout_expected,
            provided_api=provided_api,
            vpn=vpn,
        )

    return _factory


# ===========================================================================
# VPN TAGS — composable VPN configuration
# ===========================================================================


@pytest.fixture(name="vpn_tags")
def _vpn_tags() -> List[ConnectionTag]:
    """Default: no VPN servers. Override in test module or conftest to add VPN."""
    return []


# ===========================================================================
# ENVIRONMENT FIXTURES
# ===========================================================================


# --- Optional VPN-side connection (for ping-back) ---


@pytest_asyncio.fixture(name="vpn_server_connection")
async def _vpn_server_connection(
    vpn_conf: VpnConfig,
    setup_connections_factory: Callable[..., Awaitable[List[ConnectionManager]]],
) -> Optional[ConnectionManager]:
    """When *vpn_conf.should_ping_client* is True, establish a connection
    to the VPN server container and return its ``ConnectionManager``.
    Otherwise return ``None``.
    """
    if vpn_conf.should_ping_client:
        managers = await setup_connections_factory([vpn_conf.conn_tag])
        return managers[0]
    return None


@pytest_asyncio.fixture(name="dual_vpn_server_connections")
async def _dual_vpn_server_connections(
    setup_connections_factory: Callable[..., Awaitable[List[ConnectionManager]]],
) -> Tuple[ConnectionManager, ConnectionManager]:
    """Establish connections to both VPN server containers for reconnect tests."""
    vpn_1, vpn_2 = await setup_connections_factory(
        [ConnectionTag.DOCKER_VPN_1, ConnectionTag.DOCKER_VPN_2]
    )
    return vpn_1, vpn_2


@pytest_asyncio.fixture(name="single_vpn_server_connection")
async def _single_vpn_server_connection(
    setup_connections_factory: Callable[..., Awaitable[List[ConnectionManager]]],
) -> ConnectionManager:
    """Establish a connection to the VPN server for key-change tests."""
    managers = await setup_connections_factory([ConnectionTag.DOCKER_VPN_1])
    return managers[0]


# ---------------------------------------------------------------------------
# Auto-detection of *_setup_params fixtures
# ---------------------------------------------------------------------------

_PARAM_NAMES = ["alpha_setup_params", "beta_setup_params", "gamma_setup_params"]


def _resolve_setup_params(request: pytest.FixtureRequest) -> List[SetupParameters]:
    """Dynamically resolve available *_setup_params fixtures.

    Tries alpha, beta, gamma in order. Stops at the first missing fixture.
    At least alpha_setup_params must be available.
    """
    instances: List[SetupParameters] = []
    for name in _PARAM_NAMES:
        try:
            instances.append(request.getfixturevalue(name))
        except pytest.FixtureLookupError:
            break
    if not instances:
        raise ValueError(
            "env_mesh/env fixture requires at least alpha_setup_params to be "
            "parametrized on the test"
        )
    return instances


# ---------------------------------------------------------------------------
# env_mesh — dynamic mesh environment (auto-detects available *_setup_params)
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(name="env_mesh")
async def _env_mesh(
    request: pytest.FixtureRequest,
    exit_stack: AsyncExitStack,
    vpn_tags: List[ConnectionTag],
) -> Environment:
    """Dynamic mesh environment. Auto-detects available *_setup_params fixtures."""
    instances = _resolve_setup_params(request)
    return await _setup_mesh_nodes(
        exit_stack,
        instances,
        vpn=vpn_tags or None,
    )


# ---------------------------------------------------------------------------
# env — dynamic non-mesh environment (auto-detects available *_setup_params)
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(name="env")
async def _env(
    request: pytest.FixtureRequest,
    exit_stack: AsyncExitStack,
    vpn_tags: List[ConnectionTag],
) -> Environment:
    """Dynamic non-mesh environment. Auto-detects available *_setup_params fixtures."""
    instances = _resolve_setup_params(request)
    return await exit_stack.enter_async_context(
        _setup_environment(
            exit_stack,
            instances,
            vpn=vpn_tags or None,
        )
    )


# ---------------------------------------------------------------------------
# env_mesh_3node_ring_fw — 3-node mesh, ring firewall (no extractors)
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(name="env_mesh_3node_ring_fw")
async def _env_mesh_3node_ring_fw(
    exit_stack: AsyncExitStack,
    alpha_setup_params: SetupParameters,
    beta_setup_params: SetupParameters,
    gamma_setup_params: SetupParameters,
) -> Environment:
    """Set up a 3-node mesh with default_config_three_nodes and ring-shaped
    firewall restrictions (each node blocks incoming from one peer)."""
    api = API()
    alpha, beta, gamma = api.default_config_three_nodes()

    alpha.set_peer_firewall_settings(beta.id, allow_incoming_connections=False)
    beta.set_peer_firewall_settings(gamma.id, allow_incoming_connections=False)
    gamma.set_peer_firewall_settings(alpha.id, allow_incoming_connections=False)

    return await _setup_mesh_nodes(
        exit_stack,
        [alpha_setup_params, beta_setup_params, gamma_setup_params],
        provided_api=api,
    )
