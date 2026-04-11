"""Logging compatibility helpers for dependency-light offline validation."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


class _Processors:
    class TimeStamper:
        def __init__(self, fmt: str = "iso") -> None:
            self.fmt = fmt

        def __call__(
            self,
            logger: logging.Logger,
            method_name: str,
            event_dict: dict[str, Any],
        ) -> dict[str, Any]:
            if self.fmt == "iso":
                event_dict.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            return event_dict

    class JSONRenderer:
        def __call__(
            self,
            logger: logging.Logger,
            method_name: str,
            event_dict: dict[str, Any],
        ) -> str:
            return json.dumps(event_dict, sort_keys=True, default=str)


class _Stdlib:
    @staticmethod
    def add_log_level(
        logger: logging.Logger,
        method_name: str,
        event_dict: dict[str, Any],
    ) -> dict[str, Any]:
        event_dict.setdefault("level", method_name)
        return event_dict


class _BoundLogger:
    def __init__(self, name: str | None = None) -> None:
        self._logger = logging.getLogger(name)

    def info(self, event: str, **kwargs: Any) -> None:
        self._logger.info("%s %s", event, kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._logger.warning("%s %s", event, kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._logger.error("%s %s", event, kwargs)


class _StructlogFallback:
    processors = _Processors()
    stdlib = _Stdlib()

    @staticmethod
    def configure(**kwargs: Any) -> None:
        """Accept structlog-style configuration calls without requiring structlog."""

    @staticmethod
    def get_logger(name: str | None = None) -> _BoundLogger:
        return _BoundLogger(name)


def _supports_structlog_api(candidate: Any) -> bool:
    """Return True when the imported structlog object exposes the APIs we use."""
    processors = getattr(candidate, "processors", None)
    stdlib = getattr(candidate, "stdlib", None)
    return all(
        [
            hasattr(candidate, "configure"),
            hasattr(candidate, "get_logger"),
            hasattr(processors, "TimeStamper"),
            hasattr(processors, "JSONRenderer"),
            hasattr(stdlib, "add_log_level"),
        ]
    )


try:
    import structlog as _structlog  # type: ignore[import]
except ModuleNotFoundError:
    structlog = _StructlogFallback()
else:
    structlog = _structlog if _supports_structlog_api(_structlog) else _StructlogFallback()
