from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import structlog

from storage.clickhouse_client import ClickHouseClient

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class TimeWindow:
    start: dt.datetime
    end: dt.datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("TimeWindow requires timezone-aware datetimes")
        if self.end <= self.start:
            raise ValueError("TimeWindow end must be after start")


class BaseAgent(ABC):
    name: str

    def __init__(self, ch: ClickHouseClient) -> None:
        self.ch = ch

    @abstractmethod
    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError

