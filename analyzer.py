"""
analyzer.py - measurements turned into numbers, then into a diagnosis.

The module has two layers.

Phase 3 layer (statistics)
    RTT statistics (minimum / average / maximum) and packet-loss calculation for
    every hop.

Phase 4 layer (analysis)
    Hop-to-hop latency comparison, the persistence rule, classification and the
    overall assessment.

Everything lives in one module so the whole analysis can be unit tested without
a network connection.

Vocabulary used throughout
--------------------------
observed_rtts   every RTT sample that could actually be measured for a hop
avg_rtt         mean of those samples, i.e. the cost of the path up to that hop
loss_percent    (probes sent - replies received) / probes sent * 100
elevation       a hop whose average RTT is much higher than the previous
                responding hop
persistent      an elevation that is still visible in the following hops, which
                is the only trustworthy evidence of real path degradation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from traceroute import Hop

STATUS_NORMAL = "NORMAL"
STATUS_POSSIBLE_DELAY = "POSSIBLE DELAY"
STATUS_PERSISTENT_SLOWDOWN = "PERSISTENT SLOWDOWN"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_DESTINATION = "DESTINATION"

KIND_NORMAL = "NORMAL"
KIND_POSSIBLE_DELAY = "POSSIBLE_DELAY"
KIND_PERSISTENT_SLOWDOWN = "PERSISTENT_SLOWDOWN"
KIND_TEMPORARY_ANOMALY = "TEMPORARY_ICMP_ANOMALY"
KIND_TIMEOUT = "TIMEOUT"
KIND_DESTINATION = "DESTINATION"

ASSESSMENT_DEGRADED = "POSSIBLE PATH DEGRADATION"
ASSESSMENT_CLEAN = "NO PERSISTENT SLOWDOWN DETECTED"
ASSESSMENT_UNREACHABLE = "NO RESPONDING HOPS FOUND"
ASSESSMENT_UNLOCALISED = "INCREASED PATH LATENCY, SLOW HOP NOT IDENTIFIED"

DELTA_THRESHOLD_MS = 20.0
RATIO_THRESHOLD = 2.0
PERSISTENCE_HOPS = 2
PERSISTENCE_TOLERANCE = 0.75
HIGH_LOSS_PERCENT = 50.0
BASE_RTT_FLOOR_MS = 5.0

STATUS_BY_KIND = {
    KIND_NORMAL: STATUS_NORMAL,
    KIND_POSSIBLE_DELAY: STATUS_POSSIBLE_DELAY,
    KIND_PERSISTENT_SLOWDOWN: STATUS_PERSISTENT_SLOWDOWN,
    KIND_TEMPORARY_ANOMALY: STATUS_POSSIBLE_DELAY,
    KIND_TIMEOUT: STATUS_TIMEOUT,
    KIND_DESTINATION: STATUS_DESTINATION,
}


@dataclass
class HopStats:
    """Measurement summary of a single hop."""

    hop: int
    address: Optional[str]
    sent: int
    received: int
    loss_percent: float
    min_rtt: Optional[float]
    avg_rtt: Optional[float]
    max_rtt: Optional[float]
    responded: bool
    timed_out: bool
    is_destination: bool
    echo_suppressed: bool

    @property
    def has_rtt(self) -> bool:
        return self.avg_rtt is not None

    @property
    def lost(self) -> int:
        return max(0, self.sent - self.received)

    @property
    def rtt_spread(self) -> float:
        """max - min, i.e. how unstable the hop's latency is."""
        if self.min_rtt is None or self.max_rtt is None:
            return 0.0
        return self.max_rtt - self.min_rtt


def rtt_summary(rtts: Sequence[float]) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """Return (min, average, max) RTT, or (None, None, None) for no samples."""
    values = [value for value in rtts if value is not None and value >= 0]
    if not values:
        return None, None, None
    return min(values), sum(values) / len(values), max(values)


def loss_percent(sent: int, received: int) -> float:
    """Percentage of probes that were never answered."""
    if sent <= 0:
        return 0.0
    return max(0, sent - received) * 100.0 / sent


def compute_stats(hop: Hop) -> HopStats:
    """Build the statistics record for one discovered hop."""
    rtts = hop.observed_rtts
    min_rtt, avg_rtt, max_rtt = rtt_summary(rtts)
    return HopStats(
        hop=hop.number,
        address=hop.address,
        sent=hop.probes_sent,
        received=hop.received,
        loss_percent=loss_percent(hop.probes_sent, hop.received),
        min_rtt=min_rtt,
        avg_rtt=avg_rtt,
        max_rtt=max_rtt,
        responded=hop.responded,
        timed_out=hop.timed_out,
        is_destination=hop.is_destination,
        echo_suppressed=hop.echo_suppressed,
    )


def compute_all(hops: Iterable[Hop]) -> List[HopStats]:
    """Statistics for every hop of the path, in hop order."""
    return [compute_stats(hop) for hop in hops]


def path_total_rtt(stats: Sequence[HopStats]) -> float:
    """Average RTT of the last responding hop, i.e. the full path cost."""
    for entry in reversed(list(stats)):
        if entry.avg_rtt is not None:
            return entry.avg_rtt
    return 0.0


@dataclass
class HopVerdict:
    """Classification of one hop together with the evidence behind it."""

    hop: int
    address: Optional[str]
    kind: str
    status: str
    avg_rtt: Optional[float] = None
    previous_hop: Optional[int] = None
    previous_avg: Optional[float] = None
    increase: Optional[float] = None
    elevated_hops: Tuple[int, ...] = ()
    loss_percent: float = 0.0

    @property
    def is_elevated(self) -> bool:
        return self.kind in (KIND_PERSISTENT_SLOWDOWN, KIND_POSSIBLE_DELAY, KIND_TEMPORARY_ANOMALY)

    @property
    def is_persistent(self) -> bool:
        return self.kind == KIND_PERSISTENT_SLOWDOWN


@dataclass
class Analysis:
    """Complete result of the latency analysis for one traced path."""

    verdicts: List[HopVerdict] = field(default_factory=list)
    destination_reached: bool = False

    @property
    def statuses(self) -> Dict[int, str]:
        return {verdict.hop: verdict.status for verdict in self.verdicts}

    @property
    def verdict_for(self) -> Dict[int, HopVerdict]:
        return {verdict.hop: verdict for verdict in self.verdicts}

    @property
    def persistent_findings(self) -> List[HopVerdict]:
        return [verdict for verdict in self.verdicts if verdict.is_persistent]

    @property
    def delay_findings(self) -> List[HopVerdict]:
        return [verdict for verdict in self.verdicts if verdict.kind == KIND_POSSIBLE_DELAY]

    @property
    def temporary_anomalies(self) -> List[HopVerdict]:
        """Big spikes that did not survive the following hops (false positives)."""
        return [verdict for verdict in self.verdicts if verdict.kind == KIND_TEMPORARY_ANOMALY]

    @property
    def timeout_hops(self) -> List[HopVerdict]:
        return [verdict for verdict in self.verdicts if verdict.kind == KIND_TIMEOUT]

    @property
    def lossy_hops(self) -> List[HopVerdict]:
        return [verdict for verdict in self.verdicts if verdict.loss_percent >= HIGH_LOSS_PERCENT]

    @property
    def final_segment_jump(self) -> Optional[HopVerdict]:
        """A significant latency increase on the last hop of the path.

        Intermediate routers may delay ICMP responses, but the destination host
        answers for itself, so a jump seen only on the final hop cannot be
        dismissed as an ICMP artefact.
        """
        for verdict in self.verdicts:
            if verdict.kind != KIND_DESTINATION:
                continue
            if verdict.increase is None or verdict.previous_avg is None:
                continue
            if is_significant_increase(verdict.previous_avg, verdict.avg_rtt, verdict.increase):
                return verdict
        return None

    @property
    def unattributable_jump(self) -> Optional[HopVerdict]:
        """A latency increase at the destination that spans silent hops.

        The end-to-end time really did grow, but because the hops in between never
        answered, no single hop can be blamed.  Reporting this as path
        degradation would be a false positive, so it gets its own verdict.
        """
        jump = self.final_segment_jump
        if jump is not None and jump.previous_hop != jump.hop - 1:
            return jump
        return None

    @property
    def primary_finding(self) -> Optional[HopVerdict]:
        """The hop that best explains the slowdown, if there is one."""
        persistent = self.persistent_findings
        if persistent:
            return persistent[0]
        jump = self.final_segment_jump
        if jump is not None:
            return jump
        delays = self.delay_findings
        if delays:
            return delays[0]
        anomalies = self.temporary_anomalies
        if anomalies:
            return anomalies[0]
        return None

    @property
    def assessment(self) -> str:
        if not [verdict for verdict in self.verdicts if verdict.kind != KIND_TIMEOUT]:
            return ASSESSMENT_UNREACHABLE
        if self.persistent_findings:
            return ASSESSMENT_DEGRADED
        if self.unattributable_jump is not None:
            return ASSESSMENT_UNLOCALISED
        if self.final_segment_jump is not None:
            return ASSESSMENT_DEGRADED
        return ASSESSMENT_CLEAN


def is_significant_increase(previous_avg: float, current_avg: float, increase: float) -> bool:
    """Is the jump between two responding hops large enough to investigate?

    Three conditions must hold so that ordinary growth is not reported:
    the absolute jump must exceed DELTA_THRESHOLD_MS, it must exceed the
    BASE_RTT_FLOOR_MS, and it must be at least RATIO_THRESHOLD times the
    previous hop's average.
    """
    if increase < DELTA_THRESHOLD_MS or increase < BASE_RTT_FLOOR_MS:
        return False
    if previous_avg > 0 and current_avg / previous_avg < RATIO_THRESHOLD:
        return False
    return True


def _responding(stats: Sequence[HopStats]) -> List[HopStats]:
    """Hops that answered and produced at least one RTT sample."""
    return [entry for entry in stats if entry.responded and entry.avg_rtt is not None]


def _classify_latency(
    responders: Sequence[HopStats], position: int, entry: HopStats
) -> Tuple[str, Tuple[int, ...]]:
    """Apply the persistence rule to one hop and return (kind, elevated hops)."""
    if position == 0:
        return KIND_NORMAL, ()

    previous = responders[position - 1]
    increase = entry.avg_rtt - previous.avg_rtt
    if not is_significant_increase(previous.avg_rtt, entry.avg_rtt, increase):
        return KIND_NORMAL, ()

    window = responders[position + 1 : position + 1 + PERSISTENCE_HOPS]
    peak = max([entry.avg_rtt] + [later.avg_rtt for later in window])
    elevated = tuple(later.hop for later in window if later.avg_rtt >= PERSISTENCE_TOLERANCE * peak)

    if len(elevated) >= PERSISTENCE_HOPS:
        return KIND_PERSISTENT_SLOWDOWN, elevated

    recovered = bool(window) and all(later.avg_rtt < entry.avg_rtt for later in window)
    if recovered:
        return KIND_TEMPORARY_ANOMALY, elevated
    return KIND_POSSIBLE_DELAY, elevated


def analyze(stats: Sequence[HopStats]) -> Analysis:
    """Classify every hop of the path and produce the overall assessment."""
    responders = _responding(stats)
    index_of = {id(entry): position for position, entry in enumerate(responders)}
    verdicts: List[HopVerdict] = []

    for entry in stats:
        verdict = HopVerdict(
            hop=entry.hop,
            address=entry.address,
            kind=KIND_NORMAL,
            status=STATUS_NORMAL,
            avg_rtt=entry.avg_rtt,
            loss_percent=entry.loss_percent,
        )
        if not entry.responded or entry.avg_rtt is None:
            verdict.kind = KIND_TIMEOUT
            verdict.status = STATUS_TIMEOUT
            verdicts.append(verdict)
            continue

        if entry.is_destination:
            verdict.kind = KIND_DESTINATION
            verdict.status = STATUS_DESTINATION

        position = index_of.get(id(entry))
        if position is not None:
            if not entry.is_destination:
                kind, elevated = _classify_latency(responders, position, entry)
                verdict.kind = kind
                verdict.status = STATUS_BY_KIND[kind]
                verdict.elevated_hops = elevated
            if position > 0:
                verdict.previous_hop = responders[position - 1].hop
                verdict.previous_avg = responders[position - 1].avg_rtt
                verdict.increase = entry.avg_rtt - responders[position - 1].avg_rtt

        verdicts.append(verdict)

    destination_reached = any(verdict.kind == KIND_DESTINATION for verdict in verdicts)
    return Analysis(verdicts=verdicts, destination_reached=destination_reached)


def analyze_rtts(
    averages: Sequence[float],
    start_hop: int = 1,
    lost_hops: Iterable[int] = (),
    lossy_hops: Optional[Dict[int, float]] = None,
    probes: int = 5,
) -> Analysis:
    """Convenience entry point: analyse a plain list of per-hop average RTTs.

    Used by the unit tests, where the interesting input is a sequence such as
    [5, 10, 50, 54, 58] rather than real measured data.  A None entry stands for
    a hop that did not answer, so [5, 10, None, 15] describes a path whose third
    hop was silent.  `lossy_hops` maps a hop number to its packet-loss percentage.
    """
    lost: Set[int] = set(lost_hops)
    lossy = lossy_hops or {}
    last = start_hop + len(averages) - 1
    stats: List[HopStats] = []
    for offset, value in enumerate(averages):
        number = start_hop + offset
        if value is None or number in lost:
            stats.append(
                HopStats(
                    hop=number,
                    address=None,
                    sent=probes,
                    received=0,
                    loss_percent=100.0,
                    min_rtt=None,
                    avg_rtt=None,
                    max_rtt=None,
                    responded=False,
                    timed_out=True,
                    is_destination=False,
                    echo_suppressed=False,
                )
            )
            continue
        loss = lossy.get(number, 0.0)
        stats.append(
            HopStats(
                hop=number,
                address="10.0.0.{0}".format(number),
                sent=probes,
                received=probes - int(round(probes * loss / 100.0)),
                loss_percent=loss,
                min_rtt=value,
                avg_rtt=value,
                max_rtt=value,
                responded=True,
                timed_out=False,
                is_destination=number == last,
                echo_suppressed=False,
            )
        )
    return analyze(stats)
