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
    "Note: intermediate routers may rate-limit or delay ICMP replies, so a high RTT\n"
    "at one hop alone is not sufficient evidence of network slowdown."
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

    print("\nTracing and measuring route (up to {0} seconds)...\n".format(int(max_hops * 3)))
    try:
        hops = discover_route(
            destination,
            max_hops=max_hops,
            timeout=PROBE_TIMEOUT,
            resolved_ip=resolved_ip,
            on_progress=_print_progress,
        )
        measure_route(hops, probes=probes, timeout=PROBE_TIMEOUT)
    except TracerouteError as exc:
        print("\nERROR: {0}".format(exc))
        return 1

    family = _trace_family(hops)
    if family == "IPv6":
        print("\nNote: the IPv4 trace did not reach the destination, so the path was")
        print("      traced over IPv6. Your network answers ICMP for IPv6 only.")

    stats = compute_all(hops)
    analysis = analyze(stats)

    print(utils.section("route and measurements"))
    emit(build_hop_table(stats, analysis))

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
    """One line per hop while the trace runs, so a slow run does not look hung.

    Progress output is printed without the measurements; every number shown here
    appears again in the ROUTE table once the run finishes.
    """
    if not hop.responded:
        print("  {0:<4}{1}".format(hop.number, utils.TIMEOUT_TEXT))
        return
    print("  {0:<4}{1}".format(hop.number, hop.address))


def build_hop_table(stats: Sequence[HopStats], analysis: Analysis) -> List[str]:
    """One row per hop, carrying both identity and measurements.

    The route and the per-hop statistics used to be printed as two separate
    tables that repeated the same hop numbers, addresses and averages.  They are
    merged here so each hop is described exactly once: min/avg/max show the
    latency spread that repeated probes produce, and `Status` is the verdict the
    analyser reached for that hop.

    A hop that revealed itself during discovery but ignored every echo request is
    marked `*`, because its RTT is a single tracert sample rather than the
    requested number of probes.  A plain average printed next to 100 % loss would
    otherwise look self-contradictory.
    """
    statuses = analysis.statuses
    headers = ("Hop", "IP Address", "Min", "Avg", "Max", "Loss", "Status")
    rows = []
    for entry in stats:
        mark = " *" if entry.echo_suppressed else ""
        rows.append(
            (
                entry.hop,
                entry.address if entry.responded else "*",
                utils.format_ms(entry.min_rtt, suffix=""),
                utils.format_ms(entry.avg_rtt, suffix=mark),
                utils.format_ms(entry.max_rtt, suffix=""),
                utils.format_percent(entry.loss_percent),
                statuses.get(entry.hop, ""),
            )
        )
    table = utils.format_table(headers, rows, aligns="llrrrrl", min_widths=(3, 15, 6, 7, 6, 5, 19))
    if any(entry.echo_suppressed for entry in stats):
        table.append("")
        table.append("*  RTT from tracert, not echo probes (see Analysis)")
    return table


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
    lines.append("Assessment: {0}".format(analysis.assessment))
    lines.append("")
    lines.append(CAVEAT)
    return lines


def _evidence(finding: HopVerdict) -> List[str]:
    """One line summarising the jump that triggered the finding.

    The per-hop min/avg/max are already in the route table, so only the derived
    increase is added here: it is the number that connects two table rows and is
    not visible from either one alone.
    """
    return [
        "",
        "Latency rose from {0} at Hop {1} to {2} at Hop {3} ({4}).".format(
            utils.format_ms(finding.previous_avg),
            finding.previous_hop,
            utils.format_ms(finding.avg_rtt),
            finding.hop,
            utils.format_signed_ms(finding.increase),
        ),
    ]


def _label(text: str) -> str:
    return "{0:<{1}}".format(text, LABEL_WIDTH)


def _observations(
    analysis: Analysis, stats: Sequence[HopStats], max_hops: Optional[int] = None
) -> List[str]:
    """Explanatory notes about loss, silence and reachability.

    Each observation is one short paragraph.  Every fact here is also visible in
    the route table, so these lines explain *why* a number looks the way it does
    rather than repeating the number itself.
    """
    lines: List[str] = []
    timeout_hops = [verdict.hop for verdict in analysis.timeout_hops]
    reported_later: set = set()

    for run in _consecutive_runs(timeout_hops):
        later = _next_responding(analysis, run[-1])
        label = "Hop {0}".format(run[0]) if len(run) == 1 else "Hops {0}".format(utils.hop_ranges(run))
        lines.append("")
        lines.append(
                "{0} did not respond to any probe.".format(label)
                if len(run) == 1
                else "{0} did not respond to any probe ({1} hops).".format(label, len(run))
            )
        if not analysis.destination_reached:
            lines.append("The trace ran out of hops before the destination answered, so the")
            lines.append("rest of the path could not be observed in this run.")
        elif later is None:
            lines.append("No later hop answered either; the destination may be blocked.")
        else:
            reported_later.add(later)
            lines.append("Routers commonly de-prioritise ICMP, so this does not by itself")
            lines.append("mean the path is broken: Hop {0} still answers.".format(later))

    for verdict in analysis.lossy_hops:
        if verdict.kind in (KIND_TEMPORARY_ANOMALY, KIND_TIMEOUT):
            continue
        later = _next_responding(analysis, verdict.hop)
        suppressed = next(
            (
                entry
                for entry in stats
                if entry.hop == verdict.hop and entry.echo_suppressed and entry.received == 0
            ),
            None,
        )
        lines.append("")
        if suppressed is not None:
            lines.append(
                "Hop {0} answered tracert but ignored all {1} echo probes, so its RTT "
                "is a single sample (marked *).".format(verdict.hop, suppressed.sent)
            )
        else:
            lines.append(
                "Hop {0} lost {1} of its probes.".format(
                    verdict.hop, utils.format_percent(verdict.loss_percent)
                )
            )
        # A later answering hop has already been named by the silence note, so
        # repeating it here would only add a line without adding information.
        if later is not None and later in reported_later:
            pass
        elif later is not None:
            lines.append("Hop {0} still answers, so the path is not called broken.".format(later))
        elif verdict.kind == KIND_DESTINATION:
            lines.append("The loss is confined to the last segment of the path.")
        else:
            lines.append("No later hop answered, so the rest of the path cannot be described.")

    if not analysis.destination_reached:
        lines.append("")
        lines.append("The destination was not reached within the hop limit.")
        if max_hops:
            lines.append("Try a larger maximum hop count, for example {0}.".format(max_hops * 2))

    if analysis.assessment == ASSESSMENT_UNREACHABLE:
        lines.append("")
        lines.append("No hop answered, so no latency comparison is possible.")

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
