"""Base detector class defining the interface for attack detection modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Alert:
    """Represents a detected security incident."""

    title: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    source_ips: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    mitre_id: str = ""
    timestamp_start: datetime | None = None
    timestamp_end: datetime | None = None
    event_count: int = 0
    raw_samples: list[str] = field(default_factory=list)


class BaseDetector(ABC):
    """Abstract base class for all attack detectors."""

    @abstractmethod
    def detect(self, events: list[dict]) -> list[Alert]:
        """Analyze events and return a list of Alert objects."""
        pass
