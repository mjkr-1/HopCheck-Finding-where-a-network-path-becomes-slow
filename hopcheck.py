"""
hopcheck.py - HOPCHECK entry point.

Run from the VS Code terminal with:

    python hopcheck.py

The program asks for a destination, a probe count and a maximum hop count,
discovers the path, measures every hop several times, analyses the latency
profile and prints a short diagnosis.  Everything happens locally.
"""

from __future__ import annotations

import sys
from typing import List, Optional, Sequence

import utils
from analyzer import (
    ASSESSMENT_UNLOCALISED,
    ASSESSMENT_UNREACHABLE,
    KIND_DESTINATION,
    KIND_TEMPORARY_ANOMALY,
    KIND_TIMEOUT,
    Analysis,
    HopStats,
    HopVerdict,
    analyze,
    compute_all,
)
from traceroute import Hop, TracerouteError, discover_route, measure_route, resolve_destination

DEFAULT_PROBES = 5
DEFAULT_MAX_HOPS = 15
PROBE_TIMEOUT = 1.0
MIN_PROBES, MAX_PROBES = 1, 20
MIN_HOPS, MAX_HOPS = 1, 64

LABEL_WIDTH = 22

CAVEAT = (
    "Note:\n"
    "Intermediate routers may rate-limit or delay diagnostic\n"
    "responses. Therefore, a high RTT at one hop alone is not\n"
    "sufficient evidence of network slowdown."
)


def main() -> int:
    print(utils.banner())
    print()

    destination = utils.prompt_destination("Enter destination")
    probes = utils.prompt_int("Enter probes per hop", DEFAULT_PROBES, MIN_PROBES, MAX_PROBES)
    max_hops = utils.prompt_int("Enter maximum hops", DEFAULT_MAX_HOPS, MIN_HOPS, MAX_HOPS)
    print()

    emit = utils.print_lines
    resolved_ip = resolve_destination(destination)
    if not resolved_ip:
        print("Note: '{0}' could not be resolved locally. Windows will try to resolve".format(destination))
        print("      it again while tracing; an IP address can be used instead.")

    emit(
        [
            "Destination     : {0}".format(destination),
            "Resolved IP     : {0}".format(resolved_ip if resolved_ip else "unknown"),
            "Probe Count     : {0}".format(probes),
            "Maximum Hop     : {0}".format(max_hops),
            "Probe Timeout   : {0:.1f} s".format(PROBE_TIMEOUT),
        ]
    )

    print("\nTracing route (this can take up to {0} seconds)...\n".format(int(max_hops * 3)))
    try:
        hops = discover_route(
            destination,
            max_hops=max_hops,
            timeout=PROBE_TIMEOUT,
            resolved_ip=resolved_ip,
        )
        measure_route(hops, probes=probes, timeout=PROBE_TIMEOUT, on_progress=_print_progress)
    except TracerouteError as exc:
        print("\nERROR: {0}".format(exc))
        return 1

    family = _trace_family(hops)
    if family == "IPv6":
        print("\nNote: the IPv4 trace did not reach the destination, so the path was")
        print("      traced over IPv6. Your network answers ICMP for IPv6 only.")

    stats = compute_all(hops)
    analysis = analyze(stats)

    print(utils.section("route"))
    emit(build_route_table(stats, analysis))

    print(utils.section("per-hop measurements"))
    emit(build_statistics_table(stats))

    print(utils.section("analysis"))
    emit(build_analysis(analysis, stats, max_hops=max_hops))

    print("\n" + utils.rule("="))
    print()
    return 0


def _trace_family(hops: Sequence[Hop]) -> str:
    """Report which address family actually answered, so the run is self-describing."""
    for hop in hops:
        if hop.address and ":" in hop.address:
            return "IPv6"
    return "IPv4"


def _print_progress(hop: Hop) -> None:
    """One line per hop as it is measured, in the style of tracert."""
    if not hop.responded:
        print("  {0:<4}{1}".format(hop.number, utils.TIMEOUT_TEXT))
        return
    values = hop.observed_rtts
    average = sum(values) / len(values) if values else None
    print("  {0:<4}{1:<16}{2:>9}".format(hop.number, hop.address, utils.format_ms(average)))


def build_route_table(stats: Sequence[HopStats], analysis: Analysis) -> List[str]:
    """One row per hop.

    A hop that never answered an echo request but still revealed itself during
    discovery is marked with `*`, because its RTT is a single traceroute sample
    rather than the requested number of probes.  Claiming a plain average next to
    100 % loss would otherwise look self-contradictory.
    """
    statuses = analysis.statuses
    headers = ("Hop", "IP Address", "Avg RTT", "Loss", "Status")
    rows = [
        (
            entry.hop,
            entry.address if entry.responded else "*",
            utils.format_ms(entry.avg_rtt, suffix=" ms *")
            if entry.echo_suppressed
            else utils.format_ms(entry.avg_rtt),
            utils.format_percent(entry.loss_percent),
            statuses.get(entry.hop, ""),
        )
        for entry in stats
    ]
    table = utils.format_table(headers, rows, aligns="llrrl", min_widths=(3, 15, 9, 5, 19))
    if any(entry.echo_suppressed for entry in stats):
        table.append("")
        table.append("*  answered tracert but ignored ICMP echo; RTT is one traceroute sample")
    return table


def build_statistics_table(stats: Sequence[HopStats]) -> List[str]:
    headers = ("Hop", "Sent", "Recv", "Loss", "Min", "Avg", "Max")
    rows = [
        (
            entry.hop,
            entry.sent,
            entry.received,
            utils.format_percent(entry.loss_percent),
            utils.format_ms(entry.min_rtt, suffix=""),
            utils.format_ms(entry.avg_rtt, suffix=""),
            utils.format_ms(entry.max_rtt, suffix=""),
        )
        for entry in stats
    ]
    return utils.format_table(headers, rows, aligns="rrrrrrr", min_widths=(3, 4, 4, 4, 6, 6, 6))


def build_analysis(
    analysis: Analysis, stats: Sequence[HopStats], max_hops: Optional[int] = None
) -> List[str]:
    lines: List[str] = []
    finding = analysis.primary_finding

    if finding is None:
        lines.append("No significant latency increase was detected along this path.")
    elif finding.is_persistent:
        lines.append(
            "Potential persistent latency increase detected around Hop {0}.".format(finding.hop)
        )
        lines.extend(_evidence(finding))
        if finding.elevated_hops:
            lines.append("")
            lines.append(
                "Subsequent hops remained elevated ({0}).".format(_hop_list(finding.elevated_hops))
            )
    elif finding.kind == KIND_DESTINATION:
        adjacent = finding.previous_hop == finding.hop - 1
        if adjacent:
            lines.append("Latency increase detected on the final segment (Hop {0}).".format(finding.hop))
        else:
            lines.append("Latency increase detected at the destination (Hop {0}).".format(finding.hop))
        lines.extend(_evidence(finding))
        lines.append("")
        if adjacent:
            lines.append("The extra delay lies on the last segment of the path, just before")
            lines.append("the destination host answered.")
        else:
            lines.append("The delay was added somewhere between Hop {0} and Hop {1},".format(
                finding.previous_hop, finding.hop))
            lines.append("but the hops in between never answered, so the exact point")
            lines.append("where it was added cannot be determined from this run.")
    elif finding.kind == KIND_TEMPORARY_ANOMALY:
        lines.append(
            "Hop {0} shows an unusually high response time, but subsequent hops "
            "return to normal latency.".format(finding.hop)
        )
        lines.extend(_evidence(finding))
        lines.append("")
        lines.append("This may indicate delayed or rate-limited ICMP responses by that")
        lines.append("router rather than actual path degradation.")
    else:
        lines.append(
            "Latency increase observed at Hop {0}, but it was not sustained by the "
            "following hops.".format(finding.hop)
        )
        lines.extend(_evidence(finding))
        lines.append("")
        lines.append("Too few later hops stayed elevated to call this a confirmed slowdown.")
        if finding.elevated_hops:
            lines.append("Hops still elevated: {0}".format(_hop_list(finding.elevated_hops)))

    lines.extend(_observations(analysis, stats, max_hops))

    lines.append("")
    lines.append("Assessment:")
    lines.append(analysis.assessment)
    lines.append("")
    lines.append(CAVEAT)
    return lines


def _evidence(finding: HopVerdict) -> List[str]:
    return [
        "",
        "{0}: {1}  (Hop {2})".format(
            _label("Previous average RTT"),
            utils.format_ms(finding.previous_avg),
            finding.previous_hop,
        ),
        "{0}: {1}".format(
            _label("Hop {0} average RTT".format(finding.hop)),
            utils.format_ms(finding.avg_rtt),
        ),
        "{0}: {1}".format(_label("Increase"), utils.format_signed_ms(finding.increase)),
    ]


def _label(text: str) -> str:
    return "{0:<{1}}".format(text, LABEL_WIDTH)


def _observations(
    analysis: Analysis, stats: Sequence[HopStats], max_hops: Optional[int] = None
) -> List[str]:
    lines: List[str] = []
    timeout_hops = [verdict.hop for verdict in analysis.timeout_hops]

    for run in _consecutive_runs(timeout_hops):
        later = _next_responding(analysis, run[-1])
        label = "Hop {0}".format(run[0]) if len(run) == 1 else "Hops {0}".format(utils.hop_ranges(run))
        lines.append("")
        if len(run) == 1:
            lines.append("{0} did not respond to any probe.".format(label))
        else:
            lines.append("{0} did not respond to any probe ({1} hops).".format(label, len(run)))
        if not analysis.destination_reached:
            lines.append("The trace ran out of hops before the destination answered, so the")
            lines.append("rest of the path could not be observed in this run.")
        elif later is None:
            lines.append("No later hop answered either, so the path could not be traced")
            lines.append("any further. This may be a blocked or non-routable destination.")
        else:
            lines.append("Routers commonly de-prioritise or rate-limit ICMP, so silent hops do")
            lines.append("not prove the data path is broken: Hop {0} still answers.".format(later))

    if analysis.assessment == ASSESSMENT_UNLOCALISED:
        lines.append("")
        lines.append(
            "This is normal on many ISP networks, where transit routers drop ICMP but"
        )
        lines.append("still carry the traffic at full speed.")

    for verdict in analysis.lossy_hops:
        if verdict.kind == KIND_TEMPORARY_ANOMALY or verdict.kind == KIND_TIMEOUT:
            continue
        later = _next_responding(analysis, verdict.hop)
        lines.append("")
        lines.append(
            "Hop {0} lost {1} of its probes.".format(
                verdict.hop, utils.format_percent(verdict.loss_percent)
            )
        )
        if later is not None:
            lines.append("Hop {0} still answers normally, so the path is not classified".format(later))
            lines.append("as broken.")
        elif verdict.kind == KIND_DESTINATION:
            lines.append("This is the destination hop, so the loss is confined to the last")
            lines.append("segment of the path.")
        else:
            lines.append("No later hop answered, so this run cannot describe the rest of the path.")

    for entry in stats:
        if entry.echo_suppressed and entry.responded and entry.received == 0:
            lines.append("")
            lines.append(
                "Hop {0} answered traceroute but ignored ICMP echo requests;".format(entry.hop)
            )
            lines.append("its RTT comes from the traceroute sample.")

    if not analysis.destination_reached:
        lines.append("")
        lines.append("The destination was not reached within the given hop limit.")
        if max_hops:
            lines.append("Try again with a larger maximum hop count, for example {0}.".format(max_hops * 2))

    if analysis.assessment == ASSESSMENT_UNREACHABLE:
        lines.append("")
        lines.append("No hop on this path answered, so no latency comparison is possible.")

    return lines


def _consecutive_runs(numbers: Sequence[int]) -> List[List[int]]:
    """Split sorted hop numbers into runs of consecutive hops."""
    runs: List[List[int]] = []
    for number in sorted(numbers):
        if runs and number == runs[-1][-1] + 1:
            runs[-1].append(number)
        else:
            runs.append([number])
    return runs


def _next_responding(analysis: Analysis, after_hop: int) -> Optional[int]:
    """Hop number of the first responding hop after `after_hop`, if any."""
    for verdict in analysis.verdicts:
        if verdict.hop > after_hop and verdict.kind not in (KIND_TIMEOUT, KIND_TEMPORARY_ANOMALY):
            if verdict.address is not None:
                return verdict.hop
    return None


def _hop_list(hops: Sequence[int]) -> str:
    return ", ".join(str(hop) for hop in hops)


def run() -> int:
    """Entry point wrapper: the user must always be able to stop with Ctrl+C."""
    try:
        return main()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting HopCheck.")
        return 130


if __name__ == "__main__":
    sys.exit(run())
