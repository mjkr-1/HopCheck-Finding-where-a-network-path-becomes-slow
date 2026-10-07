"""Unit tests for route discovery and the Windows tracert / ping output parsers.

The parsers are pure text handling, so these tests need no network connection.
The samples below are trimmed copies of real English Windows output.
"""

import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traceroute import (  # noqa: E402
    FAST_TRACE_TIMEOUT,
    Hop,
    TracerouteError,
    build_ping_command,
    build_tracert_command,
    discover_route,
    parse_ping_output,
    parse_tracert_output,
    resolve_destination,
)

TRACERT_OUTPUT = """Tracing route to example.com [142.250.183.78] over 24 hops:
  1     192.168.1.1          1 ms      1 ms      1 ms
  2     10.0.0.1             2 ms      1 ms      2 ms
  3     *  *  *
  4     172.16.44.9         12 ms     10 ms     11 ms
  5     *     45.66.220.10   20 ms     19 ms     *
  6     142.250.183.78      24 ms     23 ms     24 ms

Trace complete.
"""

TRACERT_TEXTUAL_TIMEOUT = """Tracing route to example.com [142.250.183.78] over 24 hops:
  1     10.65.17.72         1 ms      1 ms      1 ms
  2     192.0.0.1           5 ms      3 ms      3 ms
  3     Request timed out.
  4     Request timed out.

Trace complete.
"""

PING_OUTPUT = """Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=1ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Request timed out.
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms
"""

PING_ALL_LOST = """Pinging 10.99.99.99 with 32 bytes of data:
Request timed out.
Request timed out.

Ping statistics for 10.99.99.99:
    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),
"""


class TracertParsingTests(unittest.TestCase):
    def setUp(self):
        self.hops = parse_tracert_output(TRACERT_OUTPUT, 15, "142.250.183.78")

    def test_every_hop_is_returned_in_order(self):
        self.assertEqual([hop.number for hop in self.hops], [1, 2, 3, 4, 5, 6])

    def test_addresses_are_recorded(self):
        self.assertEqual(self.hops[0].address, "192.168.1.1")
        self.assertEqual(self.hops[3].address, "172.16.44.9")

    def test_asterisk_hop_is_a_timeout(self):
        hop = self.hops[2]
        self.assertIsNone(hop.address)
        self.assertTrue(hop.timed_out)
        self.assertFalse(hop.responded)

    def test_partially_answered_hop_keeps_its_address(self):
        hop = self.hops[4]
        self.assertEqual(hop.address, "45.66.220.10")
        self.assertFalse(hop.timed_out)
        self.assertEqual(hop.discovery_rtts, [20.0, 19.0])

    def test_discovery_rtts_are_parsed(self):
        self.assertEqual(self.hops[0].discovery_rtts, [1.0, 1.0, 1.0])
        self.assertEqual(self.hops[3].discovery_rtts, [12.0, 10.0, 11.0])

    def test_destination_is_flagged(self):
        self.assertTrue(self.hops[-1].is_destination)
        self.assertFalse(self.hops[0].is_destination)

    def test_max_hops_limits_the_result(self):
        hops = parse_tracert_output(TRACERT_OUTPUT, 2, "142.250.183.78")
        self.assertEqual([hop.number for hop in hops], [1, 2])

    def test_header_lines_are_ignored(self):
        self.assertEqual(len(self.hops), 6)

    def test_textual_timeout_is_not_an_address(self):
        hops = parse_tracert_output(TRACERT_TEXTUAL_TIMEOUT, 15, "142.250.183.78")
        self.assertIsNone(hops[2].address)
        self.assertTrue(hops[2].timed_out)
        self.assertIsNone(hops[3].address)
        self.assertFalse(any(hop.is_destination for hop in hops))

    def test_empty_output_yields_no_hops(self):
        self.assertEqual(parse_tracert_output("", 15, "1.2.3.4"), [])


class PingParsingTests(unittest.TestCase):
    def test_reply_lines_become_rtt_samples(self):
        result = parse_ping_output(PING_OUTPUT, 4)
        self.assertEqual(result.rtts, [1.0, 1.0, 3.0])

    def test_sub_millisecond_reply_is_parsed(self):
        result = parse_ping_output(PING_OUTPUT, 4)
        self.assertEqual(min(result.rtts), 1.0)

    def test_loss_counters_come_from_the_summary(self):
        result = parse_ping_output(PING_OUTPUT, 4)
        self.assertEqual(result.sent, 4)
        self.assertEqual(result.received, 3)
        self.assertEqual(result.lost, 1)
        self.assertAlmostEqual(result.loss_percent, 25.0)

    def test_total_loss(self):
        result = parse_ping_output(PING_ALL_LOST, 2)
        self.assertEqual(result.rtts, [])
        self.assertEqual(result.received, 0)
        self.assertAlmostEqual(result.loss_percent, 100.0)

    def test_missing_summary_falls_back_to_requested_count(self):
        result = parse_ping_output("Reply from 1.2.3.4: bytes=32 time=7ms TTL=64", 3)
        self.assertEqual(result.sent, 3)
        self.assertEqual(result.received, 1)
        self.assertAlmostEqual(result.loss_percent, 200.0 / 3)


class CommandTests(unittest.TestCase):
    def test_tracert_command_disables_dns_and_bounds_hops(self):
        command = build_tracert_command("google.com", 12, 1.0)
        self.assertEqual(command[0], "tracert")
        self.assertIn("-d", command)
        self.assertIn("-4", command)
        self.assertEqual(command[command.index("-h") + 1], "12")
        self.assertEqual(command[command.index("-w") + 1], "1000")
        self.assertEqual(command[-1], "google.com")

    def test_ping_command_uses_fixed_count(self):
        command = build_ping_command("10.0.0.1", 5, 0.5)
        self.assertEqual(command[0], "ping")
        self.assertEqual(command[command.index("-n") + 1], "5")
        self.assertEqual(command[command.index("-w") + 1], "500")
        self.assertEqual(command[-1], "10.0.0.1")

    def test_timeout_is_rounded_to_milliseconds(self):
        command = build_ping_command("1.1.1.1", 1, 0.0004)
        self.assertEqual(command[command.index("-w") + 1], "1")

    def test_ipv4_flag_can_be_dropped(self):
        command = build_tracert_command("google.com", 12, 1.0, force_ipv4=False)
        self.assertNotIn("-4", command)
        self.assertIn("-d", command)

    def test_ipv6_address_is_not_forced_to_ipv4(self):
        command = build_ping_command("2404:6800:4007:80f::200e", 3, 1.0)
        self.assertNotIn("-4", command)
        self.assertEqual(command[-1], "2404:6800:4007:80f::200e")

    def test_ipv4_address_keeps_the_ipv4_flag(self):
        self.assertIn("-4", build_ping_command("142.250.77.142", 3, 1.0))


class HopTests(unittest.TestCase):
    def test_loss_percent(self):
        hop = Hop(number=1, address="10.0.0.1", probes_sent=5, received=3, rtts=[1.0])
        self.assertEqual(hop.lost, 2)
        self.assertAlmostEqual(hop.loss_percent, 40.0)

    def test_observed_rtts_prefers_echo_samples(self):
        hop = Hop(number=1, address="10.0.0.1", discovery_rtts=[9.0], rtts=[1.0, 2.0])
        self.assertEqual(hop.observed_rtts, [1.0, 2.0])

    def test_observed_rtts_falls_back_to_traceroute_sample(self):
        """A router that ignores echo requests still has a usable RTT."""
        hop = Hop(number=1, address="10.0.0.1", discovery_rtts=[9.0, 10.0], received=0)
        self.assertEqual(hop.observed_rtts, [9.0, 10.0])
        self.assertEqual(hop.best_rtt, 9.0)

    def test_best_rtt_is_none_without_samples(self):
        self.assertIsNone(Hop(number=1).best_rtt)

    def test_no_loss_is_reported_without_probes(self):
        self.assertAlmostEqual(Hop(number=1).loss_percent, 0.0)


class ResolutionTests(unittest.TestCase):
    def test_failed_lookup_returns_none_instead_of_raising(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
            self.assertIsNone(resolve_destination("google.com"))

    def test_ipv4_answer_is_preferred(self):
        answers = [
            socket.gaierror("no ipv4 record"),
            [
                (socket.AF_INET6, 0, 0, "", ("2001:db8::1", 0)),
                (socket.AF_INET, 0, 0, "", ("142.250.183.78", 0)),
            ],
        ]
        with mock.patch("socket.getaddrinfo", side_effect=answers):
            self.assertEqual(resolve_destination("google.com"), "142.250.183.78")

    def test_unresolvable_name_does_not_stop_the_trace(self):
        """Windows may still resolve a name that Python's resolver cannot."""
        output = TRACERT_OUTPUT
        with mock.patch("traceroute._run", return_value=output):
            hops = discover_route("google.com", max_hops=6, resolved_ip=None)
        self.assertEqual(hops[-1].is_destination, True)

    def test_windows_resolution_failure_is_explained(self):
        output = "Tracing route to bad.invalid over 30 hops\r\nUnable to resolve target system name bad.invalid.\r\n"
        with mock.patch("traceroute._run", return_value=output):
            with self.assertRaises(TracerouteError) as caught:
                discover_route("bad.invalid", max_hops=4)
        self.assertIn("could not resolve", str(caught.exception).lower())
        self.assertIn("IP address", str(caught.exception))

    def test_empty_tracert_output_is_explained(self):
        with mock.patch("traceroute._run", return_value=""):
            with self.assertRaises(TracerouteError):
                discover_route("google.com", max_hops=4)

    def test_ipv6_preferring_host_is_handled(self):
        """An IPv4-only trace may come back empty; the default family is tried next."""
        ipv6_trace = """Tracing route to google.com [2404:6800:4007:80f::200e] over 30 hops:
  1     10.65.17.72          1 ms      1 ms      1 ms
  2     2404:6800:4007:80f::200e  42 ms     40 ms     41 ms

Trace complete.
"""
        with mock.patch("traceroute._run", side_effect=["", ipv6_trace]) as runner:
            hops = discover_route("google.com", max_hops=4)
        self.assertEqual(runner.call_count, 2)
        self.assertNotIn("-4", runner.call_args_list[1][0][0])
        self.assertEqual(hops[1].address, "2404:6800:4007:80f::200e")
        self.assertEqual(build_ping_command(hops[1].address, 3, 1.0)[0], "ping")

    def test_partial_ipv4_trace_is_retried_over_ipv6(self):
        """A non-empty trace that stops short of the destination must also be retried.

        This is the real shape of an IPv6-native network: `tracert -4` answers for
        the first two ISP routers and then goes silent, while `tracert` on its own
        walks the whole path over IPv6.
        """
        ipv4_trace = """Tracing route to mcehassan.ac.in [5.175.139.118] over 20 hops:
  1     10.65.17.72          2 ms      1 ms      1 ms
  2     192.0.0.1            7 ms      7 ms      6 ms
  3     *                     *        *        *
  4     *                     *        *        *
  5     *                     *        *        *

Trace complete.
"""
        ipv6_trace = """Tracing route to mcehassan.ac.in [64:ff9b::5af:8b76] over 20 hops:
  1     2 ms     1 ms     1 ms  2409:40f2:4d:237e::a9
  2     *        *        *     Request timed out.
  3    48 ms    42 ms    32 ms  2405:200:5204:2:3925::1
  4    70 ms    14 ms    24 ms  2405:200:886:3632:62::5
  5     *        *        *     Request timed out.
  6    51 ms    38 ms    37 ms  64:ff9b::a29e:3427
  7     1 ms     1 ms     1 ms  64:ff9b::5af:8b76

Trace complete.
"""
        with mock.patch("traceroute._run", side_effect=[ipv4_trace, ipv6_trace]) as runner:
            hops = discover_route("mcehassan.ac.in", max_hops=7, resolved_ip="5.175.139.118")
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(hops[0].address, "2409:40f2:4d:237e::a9")
        self.assertEqual(hops[0].discovery_rtts, [2.0, 1.0, 1.0])
        self.assertTrue(hops[6].responded)
        self.assertEqual(len([hop for hop in hops if hop.responded]), 5)

    def test_successful_ipv4_trace_is_not_retried(self):
        with mock.patch("traceroute._run", return_value=TRACERT_OUTPUT) as runner:
            hops = discover_route("google.com", max_hops=6, resolved_ip="142.251.126.138")
        self.assertEqual(runner.call_count, 1)
        self.assertTrue(hops[-1].is_destination)


class SpeedTests(unittest.TestCase):
    """The quick discovery pass must be quick, and must never lose the route."""

    def _waits(self, runner):
        return [
            call[0][0][call[0][0].index("-w") + 1] for call in runner.call_args_list
        ]

    def test_quick_pass_waits_only_500_ms_per_reply(self):
        with mock.patch("traceroute._run", return_value=TRACERT_OUTPUT) as runner:
            discover_route("google.com", max_hops=6, resolved_ip="142.251.126.138")
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(self._waits(runner), ["500"])

    def test_quick_pass_stopping_short_falls_back_to_a_full_wait(self):
        with mock.patch(
            "traceroute._run", side_effect=[TRACERT_TEXTUAL_TIMEOUT, "", TRACERT_OUTPUT]
        ) as runner:
            hops = discover_route("google.com", max_hops=6, resolved_ip="142.251.126.138")
        self.assertEqual(self._waits(runner), ["500", "500", "1000"])
        self.assertTrue(hops[-1].is_destination)

    def test_fallback_note_is_raised_once_not_once_per_pass(self):
        notes = []
        with mock.patch(
            "traceroute._run", side_effect=[TRACERT_TEXTUAL_TIMEOUT, "", TRACERT_OUTPUT]
        ):
            discover_route(
                "google.com",
                max_hops=6,
                resolved_ip="142.251.126.138",
                on_retry=lambda: notes.append(1),
            )
        self.assertEqual(notes, [1])

    def test_no_fallback_note_when_the_quick_pass_succeeds(self):
        notes = []
        with mock.patch("traceroute._run", return_value=TRACERT_OUTPUT):
            discover_route(
                "google.com",
                max_hops=6,
                resolved_ip="142.251.126.138",
                on_retry=lambda: notes.append(1),
            )
        self.assertEqual(notes, [])

    def test_partial_quick_result_is_kept_when_nothing_reaches_the_destination(self):
        """A short trace still beats no trace, and must not raise."""
        with mock.patch(
            "traceroute._run",
            side_effect=[TRACERT_TEXTUAL_TIMEOUT, "", "", ""],
        ):
            hops = discover_route("google.com", max_hops=6, resolved_ip="142.251.126.138")
        self.assertEqual(len(hops), 4)
        self.assertTrue(hops[0].responded)
        self.assertFalse(any(hop.is_destination for hop in hops))

    def test_fast_and_slow_passes_use_the_same_command_shape(self):
        """Only -w may differ, so parsing stays valid for both passes."""
        quick = build_tracert_command("google.com", 12, FAST_TRACE_TIMEOUT)
        slow = build_tracert_command("google.com", 12, 1.0)
        self.assertEqual(
            [token for token in quick if token != quick[quick.index("-w") + 1]],
            [token for token in slow if token != slow[slow.index("-w") + 1]],
        )


if __name__ == "__main__":
    unittest.main()
