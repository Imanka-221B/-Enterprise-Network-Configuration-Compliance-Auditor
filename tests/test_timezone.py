from datetime import datetime, timezone

from utils.timezone import format_datetime_local, now_utc, parse_datetime, to_local


def test_utc_converts_to_colombo_time():
    value = "2026-08-27T04:15:00+00:00"
    local = to_local(value)
    assert local.isoformat() == "2026-08-27T09:45:00+05:30"
    assert format_datetime_local(value) == "27 Aug 2026, 09:45 AM"


def test_conversion_changes_date_at_midnight_boundary():
    local = to_local("2026-08-26T23:45:00+00:00")
    assert local.isoformat() == "2026-08-27T05:15:00+05:30"
    assert format_datetime_local("2026-08-26T23:45:00+00:00") == "27 Aug 2026, 05:15 AM"


def test_legacy_audit_timestamp_is_interpreted_as_utc():
    parsed = parse_datetime("27 Aug 2026, 04:15")
    assert parsed.tzinfo == timezone.utc
    assert format_datetime_local("27 Aug 2026, 04:15") == "27 Aug 2026, 09:45 AM"


def test_now_utc_is_timezone_aware():
    current = now_utc()
    assert current.tzinfo == timezone.utc
    assert to_local(current).tzinfo is not None
