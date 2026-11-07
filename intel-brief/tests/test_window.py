"""An edition covers the calendar day before its date, and only that day.

This is the whole point of the daily brief: a story has had a full day to be
corroborated, corrected or dropped before it is published, and the page never
mixes an hour-old report with one from two days ago. The window is derived
from the edition's date, never from the clock, so the same date rebuilt later
produces the same edition.
"""

import unittest
from datetime import date, datetime, timezone

from intel_brief.collect import _clip, _when
from intel_brief.config import day_window
from intel_brief.models import Item

EASTERN = {"site": {"timezone": "America/New_York"}}


def item(published, kind="news", ident="n1"):
    return Item(id=ident, kind=kind, source="s", title="t",
                url="https://example.test/a", published=published)


class DayWindowTest(unittest.TestCase):
    def test_covers_the_day_before_in_eastern_time(self):
        since, until = day_window(date(2026, 11, 6), EASTERN)
        # 5 November 00:00 EST (UTC-5) through 6 November 00:00 EST.
        self.assertEqual(since, datetime(2026, 11, 5, 5, tzinfo=timezone.utc))
        self.assertEqual(until, datetime(2026, 11, 6, 5, tzinfo=timezone.utc))

    def test_is_exactly_one_day(self):
        since, until = day_window(date(2026, 11, 6), EASTERN)
        self.assertEqual((until - since).total_seconds(), 24 * 3600)

    def test_summer_tracks_daylight_saving(self):
        """Midnight local stays midnight local; only the UTC offset moves."""
        since, until = day_window(date(2026, 7, 4), EASTERN)
        self.assertEqual(since, datetime(2026, 7, 3, 4, tzinfo=timezone.utc))  # EDT, UTC-4
        self.assertEqual(until, datetime(2026, 7, 4, 4, tzinfo=timezone.utc))

    def test_the_long_day_when_clocks_go_back(self):
        """1 November 2026 is 25 hours long in New York."""
        since, until = day_window(date(2026, 11, 2), EASTERN)
        self.assertEqual((until - since).total_seconds(), 25 * 3600)

    def test_the_short_day_when_clocks_go_forward(self):
        """8 March 2026 is 23 hours long in New York."""
        since, until = day_window(date(2026, 3, 9), EASTERN)
        self.assertEqual((until - since).total_seconds(), 23 * 3600)

    def test_does_not_depend_on_the_clock(self):
        self.assertEqual(day_window(date(2026, 11, 6), EASTERN),
                         day_window(date(2026, 11, 6), EASTERN))

    def test_consecutive_editions_abut_without_gap_or_overlap(self):
        _, first_until = day_window(date(2026, 11, 6), EASTERN)
        second_since, _ = day_window(date(2026, 11, 7), EASTERN)
        self.assertEqual(first_until, second_since)


class ClipTest(unittest.TestCase):
    """Feeds and social search from a start time and take whatever is newer,
    so the window has to be applied to what they return."""

    def setUp(self):
        self.since, self.until = day_window(date(2026, 11, 6), EASTERN)

    def clip(self, *items):
        return [i.id for i in _clip(list(items), self.since, self.until)]

    def test_keeps_the_covered_day(self):
        self.assertEqual(self.clip(item("2026-11-05T12:00:00Z")), ["n1"])

    def test_drops_the_morning_of_publication(self):
        """Without this the 6 November edition would carry 6 November news."""
        self.assertEqual(self.clip(item("2026-11-06T09:30:00Z")), [])

    def test_drops_the_day_before_the_covered_day(self):
        self.assertEqual(self.clip(item("2026-11-04T12:00:00Z")), [])

    def test_boundaries_are_half_open(self):
        start = item(self.since.strftime("%Y-%m-%dT%H:%M:%SZ"), ident="start")
        end = item(self.until.strftime("%Y-%m-%dT%H:%M:%SZ"), ident="end")
        self.assertEqual(self.clip(start, end), ["start"])

    def test_kev_is_exempt(self):
        """KEV entries carry a date and no time; kev.collect already picked
        the covered day, and their midnight stamp falls outside the window."""
        self.assertEqual(self.clip(item("2026-11-05T00:00:00Z", kind="kev")), ["n1"])

    def test_unreadable_timestamps_are_dropped_not_guessed(self):
        self.assertEqual(self.clip(item("not a date")), [])

    def test_offsets_and_naive_stamps_are_understood(self):
        self.assertEqual(
            self.clip(item("2026-11-05T08:00:00-05:00", ident="offset"),
                      item("2026-11-05T12:00:00", ident="naive")),
            ["offset", "naive"])


class WhenTest(unittest.TestCase):
    def test_naive_is_read_as_utc(self):
        self.assertEqual(_when(item("2026-11-05T12:00:00")),
                         datetime(2026, 11, 5, 12, tzinfo=timezone.utc))

    def test_unreadable_is_none(self):
        self.assertIsNone(_when(item("")))
        self.assertIsNone(_when(item("yesterday")))


if __name__ == "__main__":
    unittest.main()
