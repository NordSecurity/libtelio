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
    Environment,
)
from tests.helpers_vpn import VpnConfig
from tests.mesh_api import Node
from tests.telio import Client
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import (
    ConnectionManager,
    generate_connection_tracker_config,
)
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
# 2b) Factory fixture for setup_environment
# ---------------------------------------------------------------------------
@pytest.fixture(name="setup_environment_factory")
def _setup_environment_factory(
    exit_stack: AsyncExitStack,
) -> Callable[..., Awaitable[Environment]]:
    """Return a callable that forwards to helpers.setup_environment
    using the shared *exit_stack*.

    Usage inside a test::

        env = await setup_environment_factory([params], vpn=[ConnectionTag.DOCKER_VPN_1])
    """

    async def _factory(
        instances: List[SetupParameters],
        provided_api=None,
        vpn=None,
    ) -> Environment:
        return await exit_stack.enter_async_context(
            _setup_environment(
                exit_stack, instances, provided_api=provided_api, vpn=vpn
            )
        )

    return _factory


# ---------------------------------------------------------------------------
# 3) VPN-test environment fixture
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(name="vpn_environment")
async def _vpn_environment(
    exit_stack: AsyncExitStack,
    alpha_setup_params: SetupParameters,
    vpn_conf: VpnConfig,
) -> Environment:
    """Prepare a single-node VPN environment for *test_vpn_connection*.

    * Mutates *alpha_setup_params.connection_tracker_config* with the
      appropriate conntracker limits (matching the original test logic).
    * Calls ``setup_environment`` via the shared exit stack.
    """
    alpha_setup_params.connection_tracker_config = generate_connection_tracker_config(
        alpha_setup_params.connection_tag,
        stun_limits=(1, 1),
        nlx_1_limits=(
            (1, 1) if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1 else (0, 0)
        ),
        vpn_1_limits=(
            (1, 1) if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1 else (0, 0)
        ),
    )
    env = await exit_stack.enter_async_context(
        _setup_environment(exit_stack, [alpha_setup_params], vpn=[vpn_conf.conn_tag])
    )
    return env


# ---------------------------------------------------------------------------
# 4) Convenience fixtures – extract commonly used parts of the environment
# ---------------------------------------------------------------------------
@pytest.fixture(name="alpha_node")
def _alpha_node(vpn_environment: Environment) -> Node:
    """First node from the prepared VPN environment."""
    return vpn_environment.nodes[0]


@pytest.fixture(name="client_conn")
def _client_conn(vpn_environment: Environment):
    """Connection object of the first ConnectionManager."""
    return vpn_environment.connections[0].connection


@pytest.fixture(name="client_alpha")
def _client_alpha(vpn_environment: Environment) -> Client:
    """First Client instance from the prepared VPN environment."""
    return vpn_environment.clients[0]


# ---------------------------------------------------------------------------
# 5) Optional VPN-side connection (for ping-back)
# ---------------------------------------------------------------------------
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
