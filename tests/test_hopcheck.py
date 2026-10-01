"""Unit tests for the command-line layer: run(), the tables and the diagnosis text.

These build Hop records by hand, so no network connection is required.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hopcheck  # noqa: E402
from analyzer import analyze, compute_all  # noqa: E402
from traceroute import Hop  # noqa: E402


def make_hops(averages, silent=()):
    """Build a traced path from a list of average RTTs; None means 'silent'."""
    hops = []
    for number, average in enumerate(averages, start=1):
        if average is None or number in silent:
            hop = Hop(number=number, timed_out=True)
            hop.probes_sent = 5
            hops.append(hop)
            continue
        hop = Hop(number=number, address="10.0.0.{0}".format(number))
        hop.probes_sent = 5
        hop.received = 5
        hop.rtts = [average - 1.0, average, average + 1.0]
        hops.append(hop)
    for hop in hops:
        if hop.responded:
            hop.is_destination = hop is hops[-1]
    return hops


class EntryPointTests(unittest.TestCase):
    def test_run_returns_main_exit_code(self):
        with mock.patch("hopcheck.main", return_value=0):
            self.assertEqual(hopcheck.run(), 0)

    def test_ctrl_c_is_handled_gracefully(self):
        buffer = io.StringIO()
        with mock.patch("hopcheck.main", side_effect=KeyboardInterrupt):
            with redirect_stdout(buffer):
                self.assertEqual(hopcheck.run(), 130)
        self.assertIn("Interrupted", buffer.getvalue())


class TraceFamilyTests(unittest.TestCase):
    def test_ipv4_hops_are_reported_as_ipv4(self):
        self.assertEqual(hopcheck._trace_family(make_hops([2.0, 3.0])), "IPv4")

    def test_ipv6_hops_are_reported_as_ipv6(self):
        hops = make_hops([2.0, 3.0])
        hops[1].address = "2405:200:886:3632:62::5"
        self.assertEqual(hopcheck._trace_family(hops), "IPv6")


class RouteTableTests(unittest.TestCase):
    def setUp(self):
        self.hops = make_hops([3.0, 8.0, 12.0, 47.0, 51.0, 54.0])
        self.stats = compute_all(self.hops)
        self.analysis = analyze(self.stats)

    def test_table_lists_every_hop(self):
        lines = hopcheck.build_route_table(self.stats, self.analysis)
        self.assertEqual(len(lines), 2 + len(self.stats))

    def test_table_shows_status_of_each_hop(self):
        lines = hopcheck.build_route_table(self.stats, self.analysis)
        self.assertIn("PERSISTENT SLOWDOWN", "\n".join(lines))
        self.assertIn("DESTINATION", "\n".join(lines))

    def test_echo_suppressed_rtt_is_marked_in_the_route_table(self):
        """An average beside 100 % loss must be labelled, not presented as measured."""
        hops = make_hops([4.0, 6.0])
        hops[1].rtts = []
        hops[1].discovery_rtts = [6.0]
        hops[1].echo_suppressed = True
        stats = compute_all(hops)
        text = "\n".join(hopcheck.build_route_table(stats, analyze(stats)))
        self.assertIn("6.0 ms *", text)
        self.assertIn("*  answered tracert but ignored ICMP echo", text)

    def test_fully_measured_hops_carry_no_marker_or_footnote(self):
        text = "\n".join(hopcheck.build_route_table(self.stats, self.analysis))
        self.assertNotIn("answered tracert but ignored", text)
        self.assertNotIn("ms *", text)

    def test_silent_hop_is_shown_as_asterisk(self):
        hops = make_hops([4.0, None, 9.0])
        stats = compute_all(hops)
        rows = hopcheck.build_route_table(stats, analyze(stats))
        self.assertIn("TIMEOUT", "\n".join(rows))
        self.assertEqual(hops[1].probes_sent, 5)

    def test_statistics_table_has_one_row_per_hop(self):
        lines = hopcheck.build_statistics_table(self.stats)
        self.assertEqual(len(lines), 2 + len(self.stats))


class DiagnosisTests(unittest.TestCase):
    def _diagnosis(self, averages, silent=(), max_hops=None):
        hops = make_hops(averages, silent)
        stats = compute_all(hops)
        return "\n".join(hopcheck.build_analysis(analyze(stats), stats, max_hops=max_hops))

    def test_persistent_slowdown_is_reported(self):
        text = self._diagnosis([3.0, 8.0, 12.0, 47.0, 51.0, 54.0])
        self.assertIn("Potential persistent latency increase detected around Hop 4", text)
        self.assertIn("POSSIBLE PATH DEGRADATION", text)
        self.assertIn("Subsequent hops remained elevated", text)

    def test_evidence_numbers_are_printed(self):
        text = self._diagnosis([3.0, 8.0, 12.0, 47.0, 51.0, 54.0])
        self.assertIn("Previous average RTT", text)
        self.assertIn("Hop 4 average RTT", text)
        self.assertIn("Increase", text)

    def test_false_positive_is_not_called_a_slowdown(self):
        text = self._diagnosis([5.0, 10.0, 100.0, 12.0, 15.0])
        self.assertIn("subsequent hops return to normal latency", text)
        self.assertIn("delayed or rate-limited ICMP responses", text)
        self.assertIn("NO PERSISTENT SLOWDOWN DETECTED", text)

    def test_timeout_note_does_not_condemn_the_path(self):
        text = self._diagnosis([5.0, 10.0, None, 15.0])
        self.assertIn("did not respond to any probe", text)
        self.assertIn("not prove the data path is broken", text)
        self.assertIn("NO PERSISTENT SLOWDOWN DETECTED", text)

    def test_consecutive_timeouts_are_grouped(self):
        text = self._diagnosis([5.0, None, None, None, 20.0])
        self.assertIn("Hops 2-4 did not respond", text)
        self.assertEqual(text.count("did not respond"), 1)

    def test_destination_jump_between_silent_hops_is_honest(self):
        text = self._diagnosis([5.0, 10.0, None, None, 60.0])
        self.assertIn("between Hop 2 and Hop 5", text)
        self.assertIn("cannot be determined from this run", text)
        self.assertIn("SLOW HOP NOT IDENTIFIED", text)
        self.assertNotIn("POSSIBLE PATH DEGRADATION", text)

    def test_persistent_slowdown_outranks_the_unlocalised_verdict(self):
        text = self._diagnosis([5.0, 10.0, None, 50.0, 55.0, 60.0])
        self.assertIn("POSSIBLE PATH DEGRADATION", text)

    def test_destination_jump_on_last_segment_is_confident(self):
        text = self._diagnosis([5.0, 10.0, 60.0])
        self.assertIn("final segment", text)

    def test_clean_path_says_so(self):
        text = self._diagnosis([2.0, 7.0, 12.0, 15.0])
        self.assertIn("No significant latency increase was detected", text)

    def test_router_caveat_is_always_shown(self):
        for averages in ([2.0, 3.0], [5.0, 10.0, 50.0, 55.0, 60.0], [5.0, None, 9.0]):
            self.assertIn("rate-limit or delay diagnostic", self._diagnosis(averages))

    def test_unreached_destination_is_not_called_blocked(self):
        text = self._diagnosis([5.0, 10.0, None, None], max_hops=4)
        self.assertIn("ran out of hops before the destination answered", text)
        self.assertNotIn("blocked or non-routable destination", text)

    def test_unreached_destination_suggests_a_larger_hop_limit(self):
        text = self._diagnosis([5.0, 10.0, None, None], max_hops=4)
        self.assertIn("The destination was not reached within the given hop limit", text)
        self.assertIn("maximum hop count, for example 8", text)

    def test_blocked_destination_is_still_mentioned_when_hops_ran_out(self):
        text = self._diagnosis([5.0, 10.0, None, None, None, 20.0])
        self.assertNotIn("ran out of hops before the destination answered", text)


if __name__ == "__main__":
    unittest.main()
