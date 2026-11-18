"""Freeze wall-clock *dates* per run (red-team H5d).

The architect writes the current date into plan filenames/frontmatter and prompts (architect_agent/handler.py
`datetime.now(...)`), and the developer stamps `time.strftime("%Y-%m-%d")`. Without freezing, the committed-tree
SHA and the cassette request hashes change across days. The frozen instant is recorded in the cassette meta and
reused on replay.

Product code imports `from datetime import datetime` inside function bodies, so the class is replaced on the
`datetime` module itself. A metaclass keeps `isinstance(real_datetime, datetime.datetime)` true for objects
created elsewhere (C code, pydantic). Monotonic/elapsed timing (`time.time`, `time.monotonic`) is untouched.
"""
from __future__ import annotations

import datetime as _dt
import time as _time
from typing import Optional

_REAL_DATETIME = _dt.datetime
_REAL_DATE = _dt.date
_REAL_STRFTIME = _time.strftime
_FROZEN: Optional[_dt.datetime] = None


class _DTMeta(type):
    def __instancecheck__(cls, obj):  # noqa: N805
        return isinstance(obj, _REAL_DATETIME)

    def __subclasscheck__(cls, sub):  # noqa: N805
        return issubclass(sub, _REAL_DATETIME)


class _DMeta(type):
    def __instancecheck__(cls, obj):  # noqa: N805
        return isinstance(obj, _REAL_DATE)

    def __subclasscheck__(cls, sub):  # noqa: N805
        return issubclass(sub, _REAL_DATE)


class FrozenDatetime(_REAL_DATETIME, metaclass=_DTMeta):
    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        assert _FROZEN is not None
        if tz is None:
            return _FROZEN.astimezone().replace(tzinfo=None)
        return _FROZEN.astimezone(tz)

    @classmethod
    def utcnow(cls):
        assert _FROZEN is not None
        return _FROZEN.replace(tzinfo=None)

    @classmethod
    def today(cls):
        return cls.now()


class FrozenDate(_REAL_DATE, metaclass=_DMeta):
    @classmethod
    def today(cls):
        assert _FROZEN is not None
        return _FROZEN.astimezone().date()


def _frozen_strftime(fmt, t=None):  # noqa: ANN001
    if t is None:
        assert _FROZEN is not None
        return _REAL_STRFTIME(fmt, _FROZEN.astimezone().timetuple())
    return _REAL_STRFTIME(fmt, t)


def freeze(instant_iso: str) -> _dt.datetime:
    """Install the freeze for the rest of this (child) process. instant_iso must carry a UTC offset."""
    global _FROZEN
    inst = _REAL_DATETIME.fromisoformat(instant_iso)
    if inst.tzinfo is None:
        raise ValueError("frozen instant must be timezone-aware")
    _FROZEN = inst.astimezone(_dt.timezone.utc)
    _dt.datetime = FrozenDatetime  # type: ignore[misc]
    _dt.date = FrozenDate  # type: ignore[misc]
    _time.strftime = _frozen_strftime  # type: ignore[assignment]
    return _FROZEN


def now_iso_utc_seconds() -> str:
    return _REAL_DATETIME.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
