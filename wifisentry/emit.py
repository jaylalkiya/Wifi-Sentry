"""Output: JSON Lines for a SIEM, and coloured text for a human."""

from __future__ import annotations

import os
import sys
from typing import Iterable, TextIO

from .models import Event

_COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[0;36m",
}
_RESET = "\033[0m"


def _supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def write_jsonl(events: Iterable[Event], path: str) -> int:
    """Append events as one JSON object per line.

    JSONL because it is append-only, survives a crash mid-write, and is what
    every log shipper (Filebeat, Fluent Bit, Vector, Splunk UF) ingests without
    configuration. One event per line, no wrapping array.
    """
    count = 0
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.to_json() + "\n")
            count += 1
    return count


def format_event(event: Event, color: bool = False) -> str:
    tag = "[{}]".format(event.severity.upper())
    if color:
        tag = "{}{}{}".format(_COLORS.get(event.severity, ""), tag, _RESET)
    return "{} {} {}\n    {}\n    ATT&CK {} ({})".format(
        tag, event.rule_id, event.rule_name, event.message,
        event.technique, event.technique_name,
    )


def print_events(events: Iterable[Event], stream: TextIO | None = None) -> int:
    # Resolved at call time, not as a default argument: a default would bind
    # the original sys.stdout once at import and ignore any later redirect.
    stream = sys.stdout if stream is None else stream
    color = _supports_color(stream)
    count = 0
    for event in events:
        print(format_event(event, color), file=stream)
        count += 1
    return count
