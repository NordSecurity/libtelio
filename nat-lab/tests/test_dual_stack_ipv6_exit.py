from utils import Ping
from contextlib import AsyncExitStack
from mesh_api import API
from telio import AdapterType
import asyncio
import pytest
import telio
import utils.testing as testing


@pytest.mark.asyncio
async def test_ipv6_exit_node() -> None:
    pass