"""
traceroute.py - TTL-based route discovery for Windows.

Networking concept implemented here
----------------------------------
A traceroute works by sending a packet whose IPv4 TTL field is set to a small
number (1, 2, 3, ...).  Every router on the path decrements the TTL by 1 before
forwarding.  The router where the TTL reaches 0 must drop the packet and return
an ICMP "Time Exceeded" message to the sender.  The source address of that
message is the router, so by increasing the TTL one step at a time the sender
enumerates the whole path.

Why this module does not craft its own ICMP packets
---------------------------------------------------
A raw-socket implementation (Scapy / WinPcap) is not available in a plain
Python installation and would need administrator rights or an extra driver.
This project is therefore restricted to the standard library, so the Windows
system utilities are used as the probing backend:

    tracert -d -4 -h <max_hops> -w <ms> <destination>   -> path discovery
    ping   -n <count> -4 -w <ms> <hop ip>               -> RTT measurement

All Windows-specific behaviour (command names, flags, output parsing, code
pages, hidden console window) is isolated in this file so the rest of the
project stays platform-neutral.
"""

from __future__ import annotations

import locale
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

TRACERT = "tracert"
PING = "ping"

#: Windows tracert sends this many probes to every TTL position.  It is fixed:
#: this machine's tracert has no -q switch, so only the per-reply wait can be
#: shortened to make discovery faster.
TRACERT_PROBES_PER_HOP = 3

#: Per-reply wait, in seconds, used by the quick discovery pass.
#:
#: Windows tracert silently clamps `-w` to 500 ms, so anything lower behaves
#: exactly like 0.5 and any larger value only slows the trace down.  On a path
#: whose intermediate routers drop ICMP, every hop then costs
#: `TRACERT_PROBES_PER_HOP * 0.5` seconds, which is the single biggest component
#: of a run: 10 silent hops take 15 s at 0.5 s and 30 s at 1.0 s.
FAST_TRACE_TIMEOUT = 0.5

_HOP_LINE_RE = re.compile(r"^\s{0,8}(?P<hop>\d{1,3})\s+(?P<rest>\S.*)$")
_RTT_RE = re.compile(r"(?P<value>\d+(?:\.\d+)?)\s*ms\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:%-]*$")
_PING_TIME_RE = re.compile(r"time[=<]\s*(?P<value>\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_PING_PACKETS_RE = re.compile(
    r"Packets:\s*Sent\s*=\s*(?P<sent>\d+)\s*,\s*Received\s*=\s*(?P<received>\d+)",
    re.IGNORECASE,
)
_LOSS_MARKERS = (
    "request timed out",
    "destination host unreachable",
    "destination net unreachable",
    "general failure",
    "transmit failed",
    "no route to host",
    "unreachable",
)


class TracerouteError(RuntimeError):
    """Raised when route discovery cannot be performed at all."""


@dataclass
class ProbeResult:
    """Outcome of probing one host several times with ICMP echo requests."""

    sent: int = 0
    received: int = 0
    rtts: List[float] = field(default_factory=list)

    @property
    def lost(self) -> int:
        return max(0, self.sent - self.received)

    @property
    def loss_percent(self) -> float:
        if self.sent <= 0:
            return 0.0
        return self.lost * 100.0 / self.sent


@dataclass
class Hop:
    """One TTL position of the discovered path."""

    number: int
    address: Optional[str] = None
    discovery_rtts: List[float] = field(default_factory=list)
    timed_out: bool = False
    is_destination: bool = False
    probes_sent: int = 0
    received: int = 0
    rtts: List[float] = field(default_factory=list)
    echo_suppressed: bool = False

    @property
    def responded(self) -> bool:
        return self.address is not None

    @property
    def lost(self) -> int:
        return max(0, self.probes_sent - self.received)

    @property
    def loss_percent(self) -> float:
        if self.probes_sent <= 0:
            return 0.0
        return self.lost * 100.0 / self.probes_sent

    @property
    def observed_rtts(self) -> List[float]:
        """RTT values available for analysis.

        Normally the echo-probe samples are used.  Routers that ignore ICMP echo
        requests (but still answer Time Exceeded during discovery) fall back to
        the RTT that tracert measured for the same hop.
        """
        return list(self.rtts) if self.rtts else list(self.discovery_rtts)

    @property
    def best_rtt(self) -> Optional[float]:
        values = self.observed_rtts
        return min(values) if values else None


def resolve_destination(destination: str) -> Optional[str]:
    """Best-effort resolution of a destination name to an address.

    Returns None instead of raising when the local resolver cannot answer, so a
    name that only tracert can resolve (for example through a DNS configuration
    Python does not pick up) does not abort the whole run.  IPv4 is preferred,
    because a resolver that answers with AAAA records first is still usable.
    """
    ipv4 = _first_address(destination, socket.AF_INET)
    if ipv4:
        return ipv4
    return _first_address(destination, socket.AF_UNSPEC)


def _first_address(destination: str, family: int) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(destination, None, family, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    for info in infos:
        address = info[4][0]
        if family == socket.AF_INET or ":" not in address:
            return address
    return None


def build_tracert_command(
    destination: str, max_hops: int, timeout: float, force_ipv4: bool = True
) -> List[str]:
    """`tracert -d` disables reverse DNS so output is fast and purely numeric.

    `force_ipv4` adds -4.  IPv4 is tried first because this project analyses IPv4
    hops; on an IPv6-preferring host the flag can make tracert fail, so the
    caller retries without it.  `timeout` is the wait for *each* reply, so one
    hop costs up to `TRACERT_PROBES_PER_HOP * timeout` seconds when it stays
    silent.
    """
    command = [TRACERT, "-d"]
    if force_ipv4:
        command.append("-4")
    return command + [
        "-h",
        str(max_hops),
        "-w",
        str(_timeout_ms(timeout)),
        destination,
    ]


def _discovery_passes(timeout: float) -> List[Tuple[bool, bool]]:
    """`(quick, force_ipv4)` for each tracert attempt, cheapest first.

    A trace that loses every intermediate router costs
    `max_hops * TRACERT_PROBES_PER_HOP * timeout` seconds, and on a path where
    the transit routers drop ICMP that is the entire run.  Waiting 0.5 s per
    reply instead of 1 s halves that cost and is still well above the round trip
    time of a directly connected or regional hop.

    The quick passes are accepted only when they reach the destination; if they
    stop short the trace is repeated with the full `timeout`, once per address
    family.  So a too-short wait cannot make a run fail, it can only make it
    take the long way round.
    """
    return [
        (True, True),
        (True, False),
        (False, True),
        (False, False),
    ]


def _discovery_budget(timeout: float, max_hops: int) -> float:
    """Upper bound for one tracert run: three probes per hop plus start-up."""
    return TRACERT_PROBES_PER_HOP * timeout * max_hops + 10.0


def build_ping_command(address: str, count: int, timeout: float) -> List[str]:
    """`-n` sends a fixed number of echo requests instead of running forever."""
    command = [PING, "-n", str(count)]
    if _IPV4_RE.match(address):
        command.append("-4")
    return command + ["-w", str(_timeout_ms(timeout)), address]


def parse_tracert_output(output: str, max_hops: int, resolved_ip: str) -> List[Hop]:
    """Turn English Windows tracert output into a list of Hop objects.

    tracert renders a lost probe either as `*` or, depending on the Windows
    build, as the words `Request timed out.`  A textual timeout must never be
    mistaken for a responding router, so an address is only accepted from a real
    IPv4 token, or from a hostname token on a line that carries no timeout text.
    """
    hops: List[Hop] = []
    for raw_line in output.splitlines():
        match = _HOP_LINE_RE.match(raw_line)
        if match is None:
            continue
        number = int(match.group("hop"))
        if not 1 <= number <= max_hops:
            continue

        rest = match.group("rest")
        hop = Hop(
            number=number,
            timed_out=True,
            discovery_rtts=[float(m.group("value")) for m in _RTT_RE.finditer(rest)],
        )
        hop.address = _extract_address(rest)
        hop.timed_out = hop.address is None and not hop.discovery_rtts
        hop.is_destination = hop.address == resolved_ip
        hops.append(hop)

    hops.sort(key=lambda item: item.number)
    if hops and "Trace complete" in output:
        last = hops[-1]
        if last.responded:
            last.is_destination = True
    return hops


def _extract_address(rest: str) -> Optional[str]:
    """Find the responding router address in one tracert result line.

    `tracert -d` prints `<address> <rtt> <rtt> <rtt>` for short addresses, but
    swaps the columns for long ones such as IPv6, giving
    `<rtt> <rtt> <rtt> <address>`.  RTT columns are therefore filtered out
    instead of being mistaken for the address.
    """
    tokens = [token.strip("()[]") for token in rest.split() if token != "*"]
    candidates = [
        token for token in tokens if not token.isdigit() and token.lower() != "ms"
    ]
    for token in candidates:
        if _IPV4_RE.match(token):
            return token
    lowered = rest.lower()
    if any(marker in lowered for marker in _LOSS_MARKERS):
        return None
    for token in candidates:
        if _HOSTNAME_RE.match(token):
            return token
    return None


def parse_ping_output(output: str, count: int) -> ProbeResult:
    """Turn English Windows ping output into RTT samples plus loss counters.

    Reply lines give the RTT values; the trailing "Ping statistics" block gives
    the authoritative sent / received counts, so packet loss is never guessed.
    """
    rtts: List[float] = []
    saw_timeout_line = False
    for raw_line in output.splitlines():
        lowered = raw_line.lower()
        time_match = _PING_TIME_RE.search(lowered)
        if time_match:
            rtts.append(float(time_match.group("value")))
        elif any(marker in lowered for marker in _LOSS_MARKERS):
            saw_timeout_line = True

    packets_match = _PING_PACKETS_RE.search(output)
    if packets_match is not None:
        sent = int(packets_match.group("sent"))
        received = int(packets_match.group("received"))
    else:
        sent = max(count, len(rtts))
        received = len(rtts)

    if not rtts and saw_timeout_line and received > sent:
        received = sent
    return ProbeResult(sent=sent, received=received, rtts=rtts)


def probe_hop(address: str, count: int, timeout: float = 1.0) -> ProbeResult:
    """Send `count` ICMP echo requests to one hop and return the outcome."""
    command = build_ping_command(address, count, timeout)
    output = _run(command, timeout * count + 5.0)
    return parse_ping_output(output, count)


def discover_route(
    destination: str,
    max_hops: int = 15,
    timeout: float = 1.0,
    on_progress: Optional[Callable[[Hop], None]] = None,
    resolved_ip: Optional[str] = None,
    on_retry: Optional[Callable[[], None]] = None,
) -> List[Hop]:
    """Discover the path to `destination` up to `max_hops` TTL positions.

    Two things are retried here, both because a single trace can legitimately
    say nothing about a path that it can actually see.

    First the address family.  IPv4 is tried before the default family because
    a network can answer for one and stay silent for the other: an IPv6-native
    host reached with `tracert -4` often dies at the first ISP router even
    though `tracert` without the flag walks the whole path.

    Second the wait per reply.  The first two passes use `FAST_TRACE_TIMEOUT`,
    which is fast enough to be the common case; if either reaches the
    destination the run stops there.  Only when both fall short are the passes
    repeated with the full `timeout`, so an unusually slow path still gets an
    accurate trace instead of a short one.

    Whichever attempt got the most hops is kept, and `on_retry` is called once
    when the run has to fall back to the full wait.
    """
    if resolved_ip is None:
        resolved_ip = resolve_destination(destination)

    best_hops: List[Hop] = []
    notified_slowdown = False
    for quick, force_ipv4 in _discovery_passes(timeout):
        pass_timeout = FAST_TRACE_TIMEOUT if quick else timeout
        if not quick and not notified_slowdown:
            notified_slowdown = True
            if on_retry is not None:
                on_retry()

        output = _run(
            build_tracert_command(destination, max_hops, pass_timeout, force_ipv4=force_ipv4),
            _discovery_budget(pass_timeout, max_hops),
        )

        lowered = output.lower()
        if "unable to resolve" in lowered or "cannot resolve" in lowered:
            raise TracerouteError(
                "Windows could not resolve '{0}'. Either the name does not exist or this "
                "machine has no working DNS / internet connection. Try an IP address, or "
                "check the connection.".format(destination)
            )

        hops = parse_tracert_output(output, max_hops, resolved_ip or "")
        if any(hop.is_destination for hop in hops):
            best_hops = hops
            break
        if len(hops) > len(best_hops):
            best_hops = hops

    if not best_hops:
        raise TracerouteError(
            "no route information returned for '{0}'. "
            "The destination may be unreachable or the local network may block tracert.".format(
                destination
            )
        )
    if on_progress is not None:
        for hop in best_hops:
            on_progress(hop)
    return best_hops


def measure_route(
    hops: Sequence[Hop],
    probes: int = 5,
    timeout: float = 1.0,
    on_progress: Optional[Callable[[Hop], None]] = None,
) -> List[Hop]:
    """Probe every discovered hop `probes` times and fill in its measurements.

    A single RTT sample says very little, so each responding hop is measured
    repeatedly: that is what makes loss and latency-jitter detectable.  Hops that
    never answered during discovery are recorded as fully lost instead of being
    probed, and probing stops once the destination has been reached.
    """
    for hop in hops:
        if not hop.responded:
            hop.probes_sent = probes
            hop.received = 0
            hop.rtts = []
            if on_progress is not None:
                on_progress(hop)
            continue

        result = probe_hop(hop.address, probes, timeout)
        hop.probes_sent = result.sent
        hop.received = result.received
        hop.rtts = list(result.rtts)
        hop.echo_suppressed = result.sent > 0 and result.received == 0
        if on_progress is not None:
            on_progress(hop)
        if hop.is_destination:
            break
    return list(hops)


def _timeout_ms(timeout: float) -> int:
    return max(1, int(round(timeout * 1000)))


def _run(command: Sequence[str], timeout: float) -> str:
    """Run a Windows network utility, capturing its text output."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=creation_flags,
        )
    except FileNotFoundError as exc:
        raise TracerouteError(
            "'{0}' was not found. It should ship with Windows; "
            "check that your PATH is intact.".format(command[0])
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TracerouteError("'{0}' did not finish in time.".format(command[0])) from exc
    except OSError as exc:
        raise TracerouteError("could not run '{0}': {1}".format(command[0], exc)) from exc

    return completed.stdout.decode(locale.getpreferredencoding(False) or "utf-8", "replace")
