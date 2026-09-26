"""Sweep operator-declared RFC 1918 ranges through an injected prober; emit host observations.

Ported from v0.1's network sweep, keeping its two real ideas and dropping both of its defects. The
ideas: probers are injected seams, so the product never owns a scanner, and a responsive address
becomes a host claim stamped with when it was seen. The defects: it upserted straight into the
inventory (here the write path ends at a forge PR, discovery write policy), and it accepted any CIDR its caller named —
a committed `/24` from a private LAN is an identifier, so this version refuses configuration outside
RFC 1918 and outside the operator's own declared sweep allowlist before it probes a single address
(synthetic naming).

Nothing here can reach a network. The module imports no socket, no subprocess and no ICMP: a sweep
is a list of addresses plus a callable the operator supplied. There is deliberately no built-in
prober, and no way to name one from a JSON config file, because a shipped default would scan a
network this repository does not own. `worker.provider_from_config` therefore refuses a sweep
configuration and says so; a driver that holds a prober constructs `SweepProvider` itself.

The output is `discovery.Observation` values and nothing else — no write target, no resolution. A
resource this sweep stops seeing is aged out with `observed_at` evidence by `discovery.ageing`; the
sweep is one of the few sources entitled to claim `complete`, because it enumerates every address in
its configured ranges or fails. A prober that raises produces an error snapshot, never a shorter
list, because silence from a broken prober is not evidence of an absent host. Only a raised prober
does that: any other exception is this module's own bug and propagates rather than being filed as a
network result.
"""
from collections.abc import Callable, Sequence
import datetime as dt
import ipaddress
import re
from typing import Any

from . import discovery
from .validation import InvalidInventory, digest

Prober = Callable[[str], bool]
SystemInfoProber = Callable[[str], dict[str, Any] | None]

# The only address space a committed or configured sweep may sit inside. These three boundaries are
# protocol constants (RFC 1918), not one estate's ranges; tests/test_discovery_providers.py refuses
# any other CIDR literal in a provider module for exactly that reason.
RFC1918 = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
           ipaddress.ip_network('192.168.0.0/16'))
MAX_ADDRESSES = 4096
MAX_RANGES = 64
CIDR_SHAPE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
HOSTNAME_SHAPE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$')
DISCOVERED_BY = 'network-sweep'


class ProbeUnavailable(InvalidInventory):
    """The injected prober could not answer. It carries its cause; the snapshot records only a code.

    This is the only failure a sweep read turns into an error snapshot. Any other exception is a
    defect in this module and propagates: filing a bug as `prober_unavailable` would dress a broken
    scanner up as a network of silent hosts, the exact confusion this module exists to avoid.
    """


def bounded_networks(values: Sequence[Any], *, what: str,
                     inside: Sequence[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    """Parse strict IPv4 CIDR notation and refuse anything outside `inside`.

    Refusals, in order: an empty list (a sweep must name what it may touch), anything not written
    in CIDR notation (a bare address is a host, not a range, and a scan config should not guess),
    an IPv6 or non-routable network, host bits set (a typo'd range must not silently widen or
    shift), a network outside RFC 1918, and a network outside the operator's declared allowlist.
    """
    if not values or len(values) > MAX_RANGES:
        raise InvalidInventory(f'{what} must name between 1 and {MAX_RANGES} networks')
    networks = []
    for value in values:
        if not isinstance(value, str) or not CIDR_SHAPE.fullmatch(value):
            raise InvalidInventory(f'{what} needs IPv4 CIDR notation; a bare address is not a sweep range')
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise InvalidInventory(f'{what} names an invalid IPv4 network') from exc
        if network.version != 4 or str(network) != value:
            raise InvalidInventory(f'{what} must be an exact IPv4 network with no host bits set')
        if not any(network.subnet_of(boundary) for boundary in RFC1918):
            raise InvalidInventory(f'{what} may only name RFC 1918 space')
        if not any(network.subnet_of(boundary) for boundary in inside):
            raise InvalidInventory(f'{what} falls outside the declared sweep allowlist')
        networks.append(network)
    return networks


def host_count(network: ipaddress.IPv4Network) -> int:
    """How many addresses this network will probe, counted without enumerating it.

    Matches `IPv4Network.hosts()`, which drops the network and broadcast addresses above /30 and
    keeps both endpoints for the point-to-point and single-host cases.
    """
    return network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2


class SweepProvider:
    """One configured address space, probed once per tick, reported as host observations.

    `prober(address)` answers whether the address answered; `name_prober(address)` may answer a
    system-info mapping, of which exactly one key — `sysName` — is read. Every other value an agent
    returns is dropped: a device's own response is not an allowlisted field set, so it cannot widen
    what this product stores about it.
    """

    def __init__(self, *, source: str, cidrs: Sequence[str], sweep_allowlist: Sequence[str],
                 prober: Prober, name_prober: SystemInfoProber | None = None,
                 now: dt.datetime | None = None, max_addresses: int = MAX_ADDRESSES) -> None:
        """Validate the whole plan before any probe: bad configuration must cost nothing."""
        if not discovery.SOURCE_SHAPE.fullmatch(source):
            raise InvalidInventory('Sweep source must be a bounded lowercase name')
        if not callable(prober) or (name_prober is not None and not callable(name_prober)):
            raise InvalidInventory('Sweep discovery requires an injected prober callable')
        if not 1 <= max_addresses <= MAX_ADDRESSES:
            raise InvalidInventory(f'Sweep probe bound must be 1..{MAX_ADDRESSES} addresses')
        self.source = source
        self.prober = prober
        self.name_prober = name_prober
        self.now = now
        self.max_addresses = max_addresses
        allowlist = bounded_networks(sweep_allowlist, what='Sweep allowlist', inside=RFC1918)
        self.networks = bounded_networks(cidrs, what='Sweep range', inside=allowlist)
        # Bound before enumerating: the sum over ranges is an upper bound on the union, so an
        # over-wide plan is refused without ever building a 16-million-entry address list.
        planned = sum(host_count(network) for network in self.networks)
        if planned > max_addresses:
            raise InvalidInventory(f'Sweep plan probes up to {planned} addresses; the bound is '
                                   f'{max_addresses}, so narrow the ranges')
        self.addresses: dict[str, str] = {}
        for network in self.networks:
            for host in network.hosts():
                self.addresses.setdefault(str(host), str(network))
        if len(self.addresses) > max_addresses:
            raise InvalidInventory(f'Sweep plan names {len(self.addresses)} addresses; '
                                   f'the bound is {max_addresses}, so narrow the ranges')

    def observe(self) -> list[discovery.Observation]:
        """Probe each planned address exactly once and return a host claim for each responder."""
        moment = self.now or dt.datetime.now(dt.timezone.utc)
        observations = []
        for address, network in self.addresses.items():
            try:
                reachable = bool(self.prober(address))
            except Exception as exc:
                raise ProbeUnavailable('Sweep prober could not answer') from exc
            if not reachable:
                continue
            name, evidence = address, ['sweep:' + network]
            if self.name_prober is not None:
                try:
                    info = self.name_prober(address) or {}
                    sys_name = info.get('sysName') if isinstance(info, dict) else None
                except Exception as exc:
                    raise ProbeUnavailable('Sweep name prober could not answer') from exc
                if isinstance(sys_name, str) and HOSTNAME_SHAPE.fullmatch(sys_name):
                    name = sys_name
                    evidence.append('sweep:sysName')
                elif sys_name is not None:
                    # An unusable name is kept visible as evidence instead of becoming an alias no
                    # resolver can use, and never becomes the resource name.
                    evidence.append('sweep:sysName-unusable')
            aliases: list[dict[str, Any]] = [{'type': 'ip', 'value': address}]
            if name != address:
                aliases.append({'type': 'hostname', 'value': name})
            observations.append(discovery.Observation(
                source=self.source, observed_at=moment, observation_id=digest([DISCOVERED_BY, address]),
                aliases=tuple(aliases), attributes={'discovered_by': DISCOVERED_BY},
                evidence=tuple(evidence), kind='host', name=name))
        return observations

    def snapshot(self) -> dict[str, Any]:
        """Seal the sweep, or record that the probe could not run; a failed read is never a shorter list."""
        try:
            observations = self.observe()
        except ProbeUnavailable:
            # The cause is not carried into the document: it can name an address or quote a device
            # banner, and this snapshot is the whole record drift and the operator get.
            return discovery.error_snapshot(self.source, 'prober_unavailable', now=self.now)
        return discovery.snapshot(self.source, observations, now=self.now, complete=True)
