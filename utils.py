"""
utils.py - input validation and terminal formatting.

Nothing in here touches the network, which keeps it directly unit testable.
"""

from __future__ import annotations

import sys
from typing import List, Optional, Sequence

WIDTH = 60

BANNER_TITLE = "HOPCHECK"
BANNER_SUBTITLE = "Finding Where a Network Path Becomes Slow"

TIMEOUT_TEXT = "*  Request timed out."


def prompt_destination(label: str = "Enter destination") -> str:
    """Read a hostname or IP address, re-prompting until something usable is given."""
    while True:
        raw = input("{0}: ".format(label)).strip()
        if not raw:
            print("  A destination is required, for example: google.com")
            continue
        if any(character.isspace() for character in raw):
            print("  A destination cannot contain spaces.")
            continue
        if len(raw) > 253:
            print("  That destination is too long.")
            continue
        return raw


def prompt_int(
    label: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Read an integer within [minimum, maximum]; an empty answer takes the default."""
    while True:
        raw = input("{0} [{1}]: ".format(label, default)).strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("  '{0}' is not a number.".format(raw))
            continue
        if value < minimum or value > maximum:
            print("  Enter a number between {0} and {1}.".format(minimum, maximum))
            continue
        return value


def center(text: str, width: int = WIDTH) -> str:
    text = str(text)
    if len(text) >= width:
        return text
    left = (width - len(text)) // 2
    return " " * left + text


def rule(character: str = "-", width: int = WIDTH) -> str:
    return character * width


def banner(title: str = BANNER_TITLE, subtitle: str = BANNER_SUBTITLE) -> str:
    return "\n".join(
        [
            rule("="),
            center(title),
            center(subtitle),
            rule("="),
        ]
    )


def section(title: str, width: int = WIDTH) -> str:
    return "\n".join(["", title.upper(), rule("-", width), ""])


def format_ms(value: Optional[float], suffix: str = " ms") -> str:
    """Format a millisecond value for display; unknown values become '-'."""
    if value is None:
        return "-"
    return "{0:.1f}{1}".format(value, suffix)


def format_percent(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return "{0:.0f}%".format(value)


def format_signed_ms(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return "{0:+.1f} ms".format(value)


def format_address(address: Optional[str], width: int = 15) -> str:
    """Left-aligned IP address, or the classic traceroute timeout marker."""
    if not address:
        return TIMEOUT_TEXT
    return "{0:<{1}}".format(address, width)


def hop_ranges(numbers: Sequence[int]) -> str:
    """Render sorted hop numbers as compact ranges: [3,4,5,9] -> '3-5, 9'."""
    values = sorted(set(int(number) for number in numbers))
    if not values:
        return ""
    parts: List[str] = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        parts.append("{0}-{1}".format(start, previous) if previous > start else str(start))
        start = previous = value
    parts.append("{0}-{1}".format(start, previous) if previous > start else str(start))
    return ", ".join(parts)


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    aligns: str = "",
    gap: int = 2,
    min_widths: Optional[Sequence[int]] = None,
) -> List[str]:
    """Build an aligned text table with a dashed underline.

    `min_widths` keeps the layout stable when a run happens to produce only very
    short values, so consecutive runs look the same.
    """
    column_count = len(headers)
    aligns = (aligns + "l" * column_count)[:column_count]
    widths = []
    for index in range(column_count):
        widest = max([len(str(headers[index]))] + [len(str(row[index])) for row in rows])
        if min_widths is not None:
            widest = max(widest, min_widths[index])
        widths.append(widest)

    lines = [_format_row(headers, widths, aligns, gap)]
    lines.append(rule("-", sum(widths) + gap * (column_count - 1)))
    lines.extend(_format_row(row, widths, aligns, gap) for row in rows)
    return lines


def _format_row(
    cells: Sequence[object],
    widths: Sequence[int],
    aligns: str,
    gap: int = 2,
) -> str:
    padding = " " * gap
    parts = []
    for index, cell in enumerate(cells):
        text = str(cell)
        align = aligns[index]
        if align == "r":
            parts.append("{0:>{1}}".format(text, widths[index]))
        elif align == "c":
            parts.append("{0:^{1}}".format(text, widths[index]))
        else:
            parts.append("{0:<{1}}".format(text, widths[index]))
    return padding.join(parts).rstrip()


def print_lines(lines: Sequence[str], stream=None) -> None:
    out = stream or sys.stdout
    for line in lines:
        print(line, file=out)
