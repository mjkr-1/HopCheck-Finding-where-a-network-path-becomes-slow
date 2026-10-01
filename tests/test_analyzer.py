"""Unit tests for the HopCheck analysis logic.

No network access and no external dependencies: the analysis is fed with fixed
latency sequences, so the results are deterministic and the tests run offline.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (  # noqa: E402
    ASSESSMENT_CLEAN,
    ASSESSMENT_DEGRADED,
    ASSESSMENT_UNLOCALISED,
    ASSESSMENT_UNREACHABLE,
    KIND_DESTINATION,
    KIND_PERSISTENT_SLOWDOWN,
    KIND_TEMPORARY_ANOMALY,
    KIND_TIMEOUT,
    STATUS_DESTINATION,
    STATUS_NORMAL,
    STATUS_PERSISTENT_SLOWDOWN,
    STATUS_TIMEOUT,
    analyze_rtts,
    is_significant_increase,
    loss_percent,
    rtt_summary,
)


class RttStatisticsTests(unittest.TestCase):
    def test_min_average_max(self):
        self.assertEqual(rtt_summary([5, 8, 10, 12]), (5.0, 8.75, 12.0))

    def test_single_sample(self):
        self.assertEqual(rtt_summary([42]), (42.0, 42.0, 42.0))

    def test_no_samples_returns_none(self):
        self.assertEqual(rtt_summary([]), (None, None, None))

    def test_loss_percent(self):
        self.assertAlmostEqual(loss_percent(5, 5), 0.0)
        self.assertAlmostEqual(loss_percent(5, 3), 40.0)
        self.assertAlmostEqual(loss_percent(4, 0), 100.0)

    def test_loss_percent_never_negative(self):
        self.assertEqual(loss_percent(5, 5), 0.0)
        self.assertEqual(loss_percent(0, 0), 0.0)


class ThresholdTests(unittest.TestCase):
    def test_small_absolute_increase_ignored(self):
        self.assertFalse(is_significant_increase(10.0, 15.0, 5.0))

    def test_large_relative_but_tiny_absolute_ignored(self):
        self.assertFalse(is_significant_increase(1.0, 5.0, 4.0))

    def test_large_absolute_but_small_ratio_ignored(self):
        self.assertFalse(is_significant_increase(100.0, 115.0, 15.0))

    def test_large_jump_detected(self):
        self.assertTrue(is_significant_increase(12.0, 47.0, 35.0))


class NormalPathTests(unittest.TestCase):
    """TEST 1: 5, 8, 10, 12 -> NORMAL."""

    def setUp(self):
        self.analysis = analyze_rtts([5, 8, 10, 12])

    def test_no_findings(self):
        self.assertEqual(self.analysis.persistent_findings, [])
        self.assertEqual(self.analysis.temporary_anomalies, [])
        self.assertIsNone(self.analysis.primary_finding)

    def test_hops_are_normal(self):
        self.assertEqual(self.analysis.statuses[1], STATUS_NORMAL)
        self.assertEqual(self.analysis.statuses[2], STATUS_NORMAL)
        self.assertEqual(self.analysis.statuses[3], STATUS_NORMAL)

    def test_assessment_is_clean(self):
        self.assertEqual(self.analysis.assessment, ASSESSMENT_CLEAN)


class PersistentSlowdownTests(unittest.TestCase):
    """TEST 2: 5, 10, 50, 54, 58 -> PERSISTENT SLOWDOWN beginning around Hop 3."""

    def setUp(self):
        self.analysis = analyze_rtts([5, 10, 50, 54, 58])

    def test_hop_three_is_persistent_slowdown(self):
        self.assertEqual(self.analysis.statuses[3], STATUS_PERSISTENT_SLOWDOWN)

    def test_finding_points_at_hop_three(self):
        finding = self.analysis.primary_finding
        self.assertIsNotNone(finding)
        self.assertEqual(finding.hop, 3)
        self.assertEqual(finding.kind, KIND_PERSISTENT_SLOWDOWN)
        self.assertEqual(finding.previous_hop, 2)
        self.assertAlmostEqual(finding.increase, 40.0)

    def test_later_hops_recorded_as_elevated(self):
        finding = self.analysis.primary_finding
        self.assertEqual(finding.elevated_hops, (4, 5))

    def test_assessment_reports_degradation(self):
        self.assertEqual(self.analysis.assessment, ASSESSMENT_DEGRADED)

    def test_early_hops_stay_normal(self):
        self.assertEqual(self.analysis.statuses[1], STATUS_NORMAL)
        self.assertEqual(self.analysis.statuses[2], STATUS_NORMAL)

    def test_persistence_needs_two_following_hops(self):
        """A jump with only one hop behind it cannot be confirmed yet."""
        analysis = analyze_rtts([5, 10, 50, 55])
        verdict = analysis.verdict_for[3]
        self.assertEqual(verdict.status, "POSSIBLE DELAY")
        self.assertEqual(analysis.persistent_findings, [])
        self.assertEqual(analysis.assessment, ASSESSMENT_CLEAN)


class TemporaryAnomalyTests(unittest.TestCase):
    """TEST 3: 5, 10, 100, 12, 15 -> TEMPORARY / ICMP RESPONSE ANOMALY."""

    def setUp(self):
        self.analysis = analyze_rtts([5, 10, 100, 12, 15])

    def test_spike_is_flagged_as_temporary(self):
        self.assertEqual(len(self.analysis.temporary_anomalies), 1)
        self.assertEqual(self.analysis.temporary_anomalies[0].hop, 3)

    def test_spike_is_not_a_confirmed_slowdown(self):
        self.assertEqual(self.analysis.persistent_findings, [])
        self.assertEqual(self.analysis.assessment, ASSESSMENT_CLEAN)

    def test_following_hops_return_to_normal(self):
        self.assertEqual(self.analysis.statuses[4], STATUS_NORMAL)
        self.assertEqual(self.analysis.statuses[5], STATUS_DESTINATION)

    def test_spike_recorded_as_possible_delay(self):
        verdict = self.analysis.verdict_for[3]
        self.assertEqual(verdict.kind, KIND_TEMPORARY_ANOMALY)
        self.assertAlmostEqual(verdict.increase, 90.0)

    def test_highest_rtt_alone_is_not_reported_as_slowdown(self):
        highest = max(self.analysis.verdicts, key=lambda v: v.avg_rtt or 0)
        self.assertEqual(highest.hop, 3)
        self.assertFalse(highest.is_persistent)


class TimeoutTests(unittest.TestCase):
    """TEST 4: 5, 10, timeout, 15 -> TIMEOUT / possible ICMP suppression."""

    def setUp(self):
        self.analysis = analyze_rtts([5, 10, None, 15])

    def test_silent_hop_is_classified_timeout(self):
        self.assertEqual(self.analysis.statuses[3], STATUS_TIMEOUT)
        self.assertEqual([verdict.hop for verdict in self.analysis.timeout_hops], [3])

    def test_path_is_not_called_broken(self):
        self.assertEqual(self.analysis.assessment, ASSESSMENT_CLEAN)

    def test_comparison_skips_the_silent_hop(self):
        """Hop 4 must be compared against Hop 2, not against the silent Hop 3."""
        verdict = self.analysis.verdict_for[4]
        self.assertEqual(verdict.previous_hop, 2)
        self.assertAlmostEqual(verdict.increase, 5.0)

    def test_no_false_slowdown_after_a_silent_hop(self):
        self.assertEqual(self.analysis.persistent_findings, [])


class PacketLossTests(unittest.TestCase):
    """TEST 5: loss at one intermediate hop, normal later hops -> not broken."""

    def setUp(self):
        self.analysis = analyze_rtts([5, 12, 12, 14], lossy_hops={2: 60.0})

    def test_loss_is_reported(self):
        lossy = [verdict.hop for verdict in self.analysis.lossy_hops]
        self.assertEqual(lossy, [2])

    def test_path_is_not_classified_as_broken(self):
        self.assertEqual(self.analysis.persistent_findings, [])
        self.assertEqual(self.analysis.assessment, ASSESSMENT_CLEAN)

    def test_later_hops_still_normal(self):
        self.assertEqual(self.analysis.statuses[3], STATUS_NORMAL)
        self.assertEqual(self.analysis.statuses[4], STATUS_DESTINATION)

    def test_destination_status_present(self):
        self.assertEqual(self.analysis.statuses[4], STATUS_DESTINATION)
        self.assertTrue(self.analysis.destination_reached)


class DestinationTests(unittest.TestCase):
    def test_last_hop_is_destination(self):
        analysis = analyze_rtts([3, 6, 9])
        self.assertEqual(analysis.statuses[3], STATUS_DESTINATION)
        self.assertEqual(analysis.verdict_for[3].kind, KIND_DESTINATION)

    def test_jump_on_final_segment_is_detected(self):
        analysis = analyze_rtts([5, 10, 60])
        jump = analysis.final_segment_jump
        self.assertIsNotNone(jump)
        self.assertEqual(jump.hop, 3)
        self.assertAlmostEqual(jump.increase, 50.0)
        self.assertEqual(analysis.assessment, ASSESSMENT_DEGRADED)

    def test_jump_across_silent_hops_is_not_called_degradation(self):
        """A real ISP trace: latency grew, but no hop can be blamed for it."""
        analysis = analyze_rtts([5, 10, None, None, None, None, None, None, None, 90])
        self.assertEqual(analysis.persistent_findings, [])
        self.assertEqual(analysis.unattributable_jump.hop, 10)
        self.assertEqual(analysis.assessment, ASSESSMENT_UNLOCALISED)

    def test_silent_hop_before_destination_is_still_unattributable(self):
        """The jump may be on the silent hop or on the last link: it cannot be pinned."""
        analysis = analyze_rtts([5, 10, None, 60])
        self.assertIsNotNone(analysis.unattributable_jump)
        self.assertEqual(analysis.assessment, ASSESSMENT_UNLOCALISED)

    def test_no_jump_on_final_segment(self):
        self.assertIsNone(analyze_rtts([5, 10, 14]).final_segment_jump)

    def test_destination_not_reached_is_reported(self):
        analysis = analyze_rtts([5, 8, 11], lost_hops=[])
        self.assertTrue(analysis.destination_reached)

    def test_completely_silent_path(self):
        analysis = analyze_rtts([], lost_hops=[1, 2, 3])
        self.assertEqual(analysis.assessment, ASSESSMENT_UNREACHABLE)
        self.assertIsNone(analysis.primary_finding)


if __name__ == "__main__":
    unittest.main()
