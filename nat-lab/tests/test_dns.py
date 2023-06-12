from utils import process
from contextlib import AsyncExitStack
from mesh_api import DERP_SERVERS, API
from telio import AdapterType, PathType
from utils import ConnectionTag, new_connection_by_tag
import aiodocker
import asyncio
import config
import pytest
import telio
import utils.container_util as container_util
import utils.testing as testing
from utils.asyncio_util import run_async_context
import re

ALPHA_NODE_ADDRESS = config.ALPHA_NODE_ADDRESS
BETA_NODE_ADDRESS = config.BETA_NODE_ADDRESS
DNS_SERVER_ADDRESS = config.LIBTELIO_DNS_IP


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_dns() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)
        api.assign_ip(beta.id, BETA_NODE_ADDRESS)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id, DERP_SERVERS),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id, DERP_SERVERS),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        # These calls should timeout without returning anything, but cache the peer addresses
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute()
            )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        # If everything went correctly, these calls should not timeout
        await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        alpha_response = await testing.wait_long(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert BETA_NODE_ADDRESS in alpha_response.get_stdout()

        beta_response = await testing.wait_long(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert ALPHA_NODE_ADDRESS in beta_response.get_stdout()

        # Now we disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_alpha.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute(),
            )
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_long(
                connection_beta.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute(),
            )


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_dns_port() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)
        api.assign_ip(beta.id, BETA_NODE_ADDRESS)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id, DERP_SERVERS),
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id, DERP_SERVERS),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        # These call should timeout without returning anything
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "google.com"]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        # A DNS request on port 53 should work
        await testing.wait_normal(
            connection_alpha.create_process(
                ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "google.com"]
            ).execute(),
        )

        # A DNS request on a different port should timeout
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "54", "google.com"]
                ).execute(),
            )

        # Look for beta on 53 port should work
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "beta.nord"]
            ).execute()
        )
        assert BETA_NODE_ADDRESS in alpha_response.get_stdout()

        # Look for beta on a different port should timeout
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "54", "beta.nord"]
                ).execute(),
            )

        # Disable magic dns
        await client_alpha.disable_magic_dns()
        await client_beta.disable_magic_dns()

        # And as a result these calls should timeout again
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "google.com"]
                ).execute(),
            )

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["dig", "@" + DNS_SERVER_ADDRESS, "-p", "53", "beta.nord"]
                ).execute(),
            )


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_vpn_dns() -> None:
    async with AsyncExitStack() as exit_stack:
        docker = await exit_stack.enter_async_context(aiodocker.Docker())
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="yIsV88+fJrRJRKyMnbK7fHCAXWzaPeAuBILeJMtfQHI=",
            public_key="Oxm/ZeHev8trOJ69sRyvX1rngZc2Gq7sXxQq4MW7bW4=",
        )
        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)

        connection = await container_util.get(docker, "nat-lab-cone-client-01-1")

        client_alpha = await exit_stack.enter_async_context(
            telio.run(
                connection,
                alpha,
            )
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )

        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], path=PathType.Any)
        )

        # After we connect to the VPN, enable magic DNS
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # Test to see if the module is working correctly
        await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # Test if the DNS module preserves CNAME records
        dns_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "-q=CNAME", "www.microsoft.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        assert "canonical name" in dns_response.get_stdout()

        # Turn off the module and see if it worked
        await client_alpha.disable_magic_dns()

        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute(),
            )

        # Test interop with meshnet
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        await client_alpha.set_meshmap(
            api.get_meshmap(alpha.id, DERP_SERVERS),
        )

        await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_dns_after_mesh_off() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)
        api.assign_ip(beta.id, BETA_NODE_ADDRESS)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id, DERP_SERVERS),
            )
        )

        # These calls should timeout without returning anything, but cache the peer addresses
        with pytest.raises(asyncio.TimeoutError):
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "google.com", DNS_SERVER_ADDRESS]
                ).execute()
            )

        await client_alpha.enable_magic_dns(["1.1.1.1"])

        # If everything went correctly, these calls should not timeout
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # If the previous calls didn't fail, we can assume that the resolver is running so no need to wait for the timeout and test the validity of the response
        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert BETA_NODE_ADDRESS in alpha_response.get_stdout()

        # Now we disable magic dns
        await client_alpha.set_mesh_off()

        # If everything went correctly, these calls should not timeout
        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        # After mesh off, .nord names should not be resolved anymore, therefore nslookup should fail
        try:
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
                ).execute(),
            )
        except process.ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout


@pytest.mark.global_tests
@pytest.mark.asyncio
@pytest.mark.timeout(60 * 5 + 60)
@pytest.mark.parametrize(
    "alpha_connection_tag,adapter_type",
    [
        pytest.param(
            ConnectionTag.DOCKER_CONE_CLIENT_1,
            AdapterType.BoringTun,
            marks=pytest.mark.long,
        ),
    ],
)
async def test_dns_stability(
    alpha_connection_tag: ConnectionTag, adapter_type: AdapterType
) -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)
        api.assign_ip(beta.id, BETA_NODE_ADDRESS)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(alpha_connection_tag)
        )

        connection_beta = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_2)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
                adapter_type,
            )
        )

        client_beta = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_beta,
                beta,
                api.get_meshmap(beta.id),
            )
        )

        await testing.wait_long(client_alpha.handshake(beta.public_key))
        await testing.wait_long(client_beta.handshake(alpha.public_key))

        await client_alpha.enable_magic_dns(["1.1.1.1"])
        await client_beta.enable_magic_dns(["1.1.1.1"])

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert BETA_NODE_ADDRESS in alpha_response.get_stdout()

        beta_response = await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert ALPHA_NODE_ADDRESS in beta_response.get_stdout()

        await asyncio.sleep(60 * 5)

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert BETA_NODE_ADDRESS in alpha_response.get_stdout()

        beta_response = await testing.wait_normal(
            connection_beta.create_process(
                ["nslookup", "alpha.nord", DNS_SERVER_ADDRESS]
            ).execute()
        )
        assert ALPHA_NODE_ADDRESS in beta_response.get_stdout()


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_set_meshmap_dns_update() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id),
            )
        )

        await client_alpha.enable_magic_dns([])

        # We should not be able to resolve beta yet, since it's not registered
        try:
            await testing.wait_normal(
                connection_alpha.create_process(
                    ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
                ).execute(),
            )
        except process.ProcessExecError as e:
            assert "server can't find beta.nord" in e.stdout

        beta = api.register(
            name="beta",
            id="7b4548ca-fe5a-4597-8513-896f38c6d6ae",
            private_key="SPFD84gPtBNc3iGY9Cdrj+mSCwBeh3mCMWfPaeWQolw=",
            public_key="Q1M3VKUcfTmGsrRzY6BpNds1yDIUvPVcs/2TySv/t1U=",
        )

        api.assign_ip(beta.id, BETA_NODE_ADDRESS)

        # Check if setting meshnet updates nord names for dns resolver
        await client_alpha.set_meshmap(
            api.get_meshmap(alpha.id, DERP_SERVERS),
        )

        alpha_response = await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "beta.nord", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        assert BETA_NODE_ADDRESS in alpha_response.get_stdout()


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_dns_update() -> None:
    async with AsyncExitStack() as exit_stack:
        docker = await exit_stack.enter_async_context(aiodocker.Docker())
        api = API()

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="yIsV88+fJrRJRKyMnbK7fHCAXWzaPeAuBILeJMtfQHI=",
            public_key="Oxm/ZeHev8trOJ69sRyvX1rngZc2Gq7sXxQq4MW7bW4=",
        )
        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)

        connection = await container_util.get(docker, "nat-lab-cone-client-01-1")

        client_alpha = await exit_stack.enter_async_context(
            telio.run(
                connection,
                alpha,
            )
        )

        wg_server = config.WG_SERVER

        await testing.wait_long(
            client_alpha.connect_to_vpn(
                wg_server["ipv4"], wg_server["port"], wg_server["public_key"]
            )
        )

        await testing.wait_lengthy(
            client_alpha.handshake(wg_server["public_key"], path=PathType.Any)
        )

        # Don't forward anything yet
        await client_alpha.enable_magic_dns([])

        alpha_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        assert "Can't find google.com: No answer" in alpha_response.get_stdout()

        # Update forward dns and check if it works now
        await client_alpha.enable_magic_dns(["1.1.1.1"])

        alpha_response = await testing.wait_normal(
            connection.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )
        # Check if some address was found
        assert "Name:	google.com\nAddress:" in alpha_response.get_stdout()


@pytest.mark.global_tests
@pytest.mark.asyncio
async def test_dns_duplicate_requests_on_multiple_forward_servers() -> None:
    async with AsyncExitStack() as exit_stack:
        api = API()

        FIRST_DNS_SERVER = "8.8.8.8"
        SECOND_DNS_SERVER = "1.1.1.1"

        alpha = api.register(
            name="alpha",
            id="96ddb926-4b86-11ec-81d3-0242ac130003",
            private_key="IGm+42FLMMGZRaQvk6F3UPbl+T/CBk8W+NPoX2/AdlU=",
            public_key="41CCEssnYIh8/8D8YvbTfWEcFanG3D0I0z1tRcN1Lyc=",
        )

        api.assign_ip(alpha.id, ALPHA_NODE_ADDRESS)

        connection_alpha = await exit_stack.enter_async_context(
            new_connection_by_tag(ConnectionTag.DOCKER_CONE_CLIENT_1)
        )

        process = connection_alpha.create_process(
            ["tcpdump", "-ni", "eth0", "udp", "and", "port", "53", "-l"]
        )
        await exit_stack.enter_async_context(run_async_context(process.execute()))

        client_alpha = await exit_stack.enter_async_context(
            telio.run_meshnet(
                connection_alpha,
                alpha,
                api.get_meshmap(alpha.id, DERP_SERVERS),
            )
        )

        await client_alpha.enable_magic_dns([FIRST_DNS_SERVER, SECOND_DNS_SERVER])

        await testing.wait_normal(
            connection_alpha.create_process(
                ["nslookup", "google.com", DNS_SERVER_ADDRESS]
            ).execute(),
        )

        await asyncio.sleep(1)

        results = re.findall(
            r".* IP .* > (?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,5}): .* A\?.*",
            process.get_stdout(),
        )

        assert results
        assert [result for result in results if FIRST_DNS_SERVER in result]
        assert not ([result for result in results if SECOND_DNS_SERVER in result])
