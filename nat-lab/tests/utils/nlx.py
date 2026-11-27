"""Inspecting WireGuard peers of the NLX VPN server."""

import asyncio
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from tests.utils.connection import Connection
from typing import Optional

NLX_INTERFACE = "nlx0"
# What `nlx show <iface> dump` prints for a peer without a preshared key
EMPTY_PRESHARED_KEY_SLOT = "(none)"
NLX_SAMPLING_PERIOD_S = 0.5


@dataclass(frozen=True)
class PqRekey:
    """A new preshared key showed up for the client's peer on the NLX server."""

    # NLX clock (unix seconds): when the new key was first seen
    at: float
    # NLX clock (unix seconds): the latest WireGuard handshake while the old key was
    # still in place
    last_wg_handshake: int

    @property
    def since_wg_handshake(self) -> float:
        return self.at - self.last_wg_handshake


async def read_nlx_peers(
    nlx_conn: Connection,
) -> tuple[float, dict[str, tuple[str, int]]]:
    """NLX server time and {public key: (preshared key, latest handshake)} of its peers.

    `nlx show <iface> dump` uses the `wg show <iface> dump` format: one interface line,
    then per peer: public-key preshared-key endpoint allowed-ips latest-handshake
    transfer-rx transfer-tx persistent-keepalive.
    """
    process = await nlx_conn.create_process(
        ["bash", "-c", f"date +%s.%N && nlx show {NLX_INTERFACE} dump"],
        quiet=True,
    ).execute()
    now, _interface, *peer_lines = process.get_stdout().splitlines()
    peers: dict[str, tuple[str, int]] = {}
    for line in peer_lines:
        public_key, preshared_key, _endpoint, _ips, latest_handshake, *_ = line.split()
        peers[public_key] = (preshared_key, int(latest_handshake))
    return float(now), peers


async def find_pq_client_public_key(nlx_conn: Connection) -> str:
    """Public key of the PQ client that has just connected, as known to NLX.

    A PQ session uses a freshly generated WireGuard key, not the node's own key, so
    take the PQ peer that handshaked most recently.
    """
    _, peers = await read_nlx_peers(nlx_conn)
    pq_peers = {
        public_key: latest_handshake
        for public_key, (preshared_key, latest_handshake) in peers.items()
        if preshared_key != EMPTY_PRESHARED_KEY_SLOT
    }
    assert pq_peers, f"no peer with a preshared key on {NLX_INTERFACE}"
    return max(pq_peers, key=lambda public_key: pq_peers[public_key])


class NlxPeerObserver:
    """Records WireGuard handshakes and preshared key changes of one NLX peer.

    nlx only reports the latest handshake and the current preshared key, so the peer
    is sampled every NLX_SAMPLING_PERIOD_S. Events closer together than that (or than
    nlx's 1s handshake resolution) can't be told apart.
    """

    def __init__(self, nlx_conn: Connection, public_key: str) -> None:
        self._nlx_conn = nlx_conn
        self._public_key = public_key
        self._preshared_key: Optional[str] = None
        self._sampler: Optional[asyncio.Task] = None
        self.wg_handshakes: list[int] = []
        self.pq_rekeys: list[PqRekey] = []
        # NLX clock (unix seconds) of the most recent sample
        self.last_sample_at = 0.0

    async def _sample(self) -> None:
        now, peers = await read_nlx_peers(self._nlx_conn)
        self.last_sample_at = now
        assert self._public_key in peers, f"peer {self._public_key} left NLX"
        preshared_key, latest_handshake = peers[self._public_key]

        if self._preshared_key is not None and preshared_key != self._preshared_key:
            # Use the handshake from the previous sample: with neptun the new key
            # triggers a handshake right away, which may already be in this sample.
            assert self.wg_handshakes, "preshared key changed before any handshake"
            self.pq_rekeys.append(PqRekey(now, self.wg_handshakes[-1]))
        self._preshared_key = preshared_key

        if latest_handshake and latest_handshake not in self.wg_handshakes[-1:]:
            self.wg_handshakes.append(latest_handshake)

    @asynccontextmanager
    async def observe(self) -> AsyncIterator["NlxPeerObserver"]:
        await self._sample()
        stop = asyncio.Event()

        async def sample_until_stopped() -> None:
            while not stop.is_set():
                await asyncio.sleep(NLX_SAMPLING_PERIOD_S)
                await self._sample()

        self._sampler = asyncio.create_task(sample_until_stopped())
        try:
            yield self
        finally:
            stop.set()
            await asyncio.gather(self._sampler, return_exceptions=True)

    async def wait_until(
        self, condition: Callable[[], bool], timeout: float, what: str
    ) -> None:
        try:
            async with asyncio.timeout(timeout):
                while not condition():
                    if self._sampler is not None and self._sampler.done():
                        self._sampler.result()  # re-raise what stopped the sampler
                    await asyncio.sleep(NLX_SAMPLING_PERIOD_S)
        except TimeoutError as e:
            raise AssertionError(
                f"no {what} within {timeout}s, timeline:\n{self.timeline()}"
            ) from e

    def timeline(self, extra_events: Sequence[tuple[float, str]] = ()) -> str:
        """Human-readable history, relative to the first observed handshake.

        `extra_events` are (NLX clock, description) pairs to show alongside.
        """
        if not self.wg_handshakes:
            return "  (no WireGuard handshakes)"
        start = self.wg_handshakes[0]
        events = [(float(t), "WireGuard handshake") for t in self.wg_handshakes]
        events += [
            (
                rekey.at,
                "new preshared key (PQ rekey),"
                f" {rekey.since_wg_handshake:.1f}s after the last WireGuard handshake",
            )
            for rekey in self.pq_rekeys
        ]
        events += extra_events
        return "\n".join(f"  +{at - start:6.1f}s {what}" for at, what in sorted(events))
