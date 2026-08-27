"""Centralized UTC storage and application-timezone display helpers."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

DEFAULT_TIMEZONE = "Asia/Colombo"


def application_timezone() -> ZoneInfo:
    return ZoneInfo(os.environ.get("ENCCA_TIMEZONE", DEFAULT_TIMEZONE))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str | datetime | None) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.strptime(str(value), "%d %b %Y, %H:%M")
            except ValueError:
                return None
    # Existing audit records used this exact naive format from UTC datetime.now().
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def to_local(value: str | datetime | None) -> datetime | None:
    parsed = parse_datetime(value)
    return parsed.astimezone(application_timezone()) if parsed else None


def format_datetime_local(value: str | datetime | None) -> str:
    local = to_local(value)
    return local.strftime("%d %b %Y, %I:%M %p") if local else "-"
