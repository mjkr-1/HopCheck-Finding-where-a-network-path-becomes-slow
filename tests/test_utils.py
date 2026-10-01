"""Unit tests for input validation and terminal formatting.

No network access: prompts are exercised by feeding scripted answers to
input(), and formatting is checked on the returned strings.
"""

import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils  # noqa: E402


@contextlib.contextmanager
def feed(answers):
    """Answer input() with `answers` in order and swallow the prompt output."""
    buffer = io.StringIO()
    with mock.patch("builtins.input", side_effect=answers) as patched:
        with contextlib.redirect_stdout(buffer):
            yield patched


class DestinationPromptTests(unittest.TestCase):
    def test_valid_hostname_is_accepted(self):
        with feed(["google.com"]):
            self.assertEqual(utils.prompt_destination(), "google.com")

    def test_whitespace_is_stripped(self):
        with feed(["  8.8.8.8  "]):
            self.assertEqual(utils.prompt_destination(), "8.8.8.8")

    def test_empty_answer_is_re_prompted(self):
        with feed(["", "example.com"]):
            self.assertEqual(utils.prompt_destination(), "example.com")

    def test_spaces_inside_are_rejected(self):
        with feed(["my host", "example.com"]):
            self.assertEqual(utils.prompt_destination(), "example.com")

    def test_overlong_destination_is_rejected(self):
        with feed(["a" * 300, "example.com"]):
            self.assertEqual(utils.prompt_destination(), "example.com")


class IntegerPromptTests(unittest.TestCase):
    def test_empty_answer_takes_the_default(self):
        with feed([""]):
            self.assertEqual(utils.prompt_int("Enter probes per hop", 5, 1, 20), 5)

    def test_valid_number_is_accepted(self):
        with feed(["7"]):
            self.assertEqual(utils.prompt_int("Enter probes per hop", 5, 1, 20), 7)

    def test_non_numeric_is_re_prompted(self):
        with feed(["abc", "3"]):
            self.assertEqual(utils.prompt_int("Enter probes per hop", 5, 1, 20), 3)

    def test_value_below_minimum_is_rejected(self):
        with feed(["0", "5"]):
            self.assertEqual(utils.prompt_int("Enter maximum hops", 15, 1, 64), 5)

    def test_value_above_maximum_is_rejected(self):
        with feed(["999", "15"]):
            self.assertEqual(utils.prompt_int("Enter maximum hops", 15, 1, 64), 15)

    def test_invalid_answers_are_all_consumed(self):
        with feed(["-3", "x", "2.5", "8"]) as patched:
            self.assertEqual(utils.prompt_int("Enter probes per hop", 5, 1, 20), 8)
            self.assertEqual(patched.call_count, 4)


class FormattingTests(unittest.TestCase):
    def test_format_ms(self):
        self.assertEqual(utils.format_ms(48.24), "48.2 ms")
        self.assertEqual(utils.format_ms(2.36), "2.4 ms")

    def test_format_ms_unknown_value(self):
        self.assertEqual(utils.format_ms(None), "-")

    def test_format_ms_without_suffix(self):
        self.assertEqual(utils.format_ms(7.0, suffix=""), "7.0")

    def test_format_percent(self):
        self.assertEqual(utils.format_percent(0.0), "0%")
        self.assertEqual(utils.format_percent(40.0), "40%")
        self.assertEqual(utils.format_percent(100.0), "100%")

    def test_format_signed_ms(self):
        self.assertEqual(utils.format_signed_ms(35.0), "+35.0 ms")
        self.assertEqual(utils.format_signed_ms(-88.0), "-88.0 ms")
        self.assertEqual(utils.format_signed_ms(None), "-")

    def test_format_address_timeout_marker(self):
        self.assertEqual(utils.format_address(None), utils.TIMEOUT_TEXT)

    def test_format_address_pads_to_width(self):
        self.assertEqual(utils.format_address("10.0.0.1", 15), "10.0.0.1       ")


class HopRangeTests(unittest.TestCase):
    def test_single_hop(self):
        self.assertEqual(utils.hop_ranges([3]), "3")

    def test_consecutive_hops_collapse(self):
        self.assertEqual(utils.hop_ranges([3, 4, 5, 6]), "3-6")

    def test_mixed_runs(self):
        self.assertEqual(utils.hop_ranges([3, 4, 5, 9, 12, 13]), "3-5, 9, 12-13")

    def test_unsorted_input_is_sorted(self):
        self.assertEqual(utils.hop_ranges([9, 3, 4]), "3-4, 9")

    def test_empty_input(self):
        self.assertEqual(utils.hop_ranges([]), "")


class LayoutTests(unittest.TestCase):
    def test_rule_width(self):
        self.assertEqual(len(utils.rule("-")), utils.WIDTH)
        self.assertEqual(len(utils.rule("=", 20)), 20)

    def test_banner_contains_title_and_subtitle(self):
        banner = utils.banner()
        self.assertIn(utils.BANNER_TITLE, banner)
        self.assertIn(utils.BANNER_SUBTITLE, banner)
        self.assertEqual(len(banner.splitlines()), 4)

    def test_section_is_uppercase_and_ruled(self):
        section = utils.section("analysis")
        lines = section.splitlines()
        self.assertEqual(lines[1], "ANALYSIS")
        self.assertEqual(lines[2], utils.rule("-"))

    def test_center_positions_text(self):
        self.assertEqual(utils.center("abc", 10), "   abc")
        self.assertEqual(utils.center("abcdef", 10), "  abcdef")

    def test_format_table_aligns_columns(self):
        headers = ("Hop", "IP Address", "Avg RTT")
        rows = [(1, "192.168.1.1", "2.3 ms"), (12, "10.0.0.1", "1234.5 ms")]
        lines = utils.format_table(headers, rows, aligns="llr")
        self.assertEqual(len(lines), 4)
        header, separator, first, second = lines
        self.assertTrue(set(separator) <= {"-"})
        self.assertGreaterEqual(len(separator), len(header))
        self.assertEqual(header.index("IP Address"), first.index("192.168.1.1"))
        self.assertEqual(header.index("Avg RTT") + 7, first.rindex("2.3 ms") + 6)
        self.assertEqual(len(second), len(first))
        self.assertEqual(second.index("1234.5 ms") + 9, header.index("Avg RTT") + 7)

    def test_format_table_respects_minimum_widths(self):
        lines = utils.format_table(("Hop", "Loss"), [(1, "0%")], aligns="rr", min_widths=(3, 5))
        self.assertEqual(lines[0], "Hop   Loss")
        self.assertEqual(lines[2], "  1     0%")

    def test_format_table_without_rows(self):
        lines = utils.format_table(("Hop", "Loss"), [], aligns="ll")
        self.assertEqual(len(lines), 2)
        self.assertTrue(set(lines[1]) <= {"-"})


if __name__ == "__main__":
    unittest.main()
