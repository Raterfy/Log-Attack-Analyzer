"""Base parser class defining the interface for all log parsers."""

from abc import ABC, abstractmethod
from datetime import datetime


class BaseParser(ABC):
    """Abstract base class for log parsers.

    Each parser must implement `parse_file` to read a log file
    and return a list of normalized event dictionaries.
    """

    @abstractmethod
    def parse_file(self, filepath: str) -> list[dict]:
        """Parse a log file and return normalized events.

        Each event dict contains at minimum:
            - timestamp: datetime or str
            - source: log type identifier
            - raw: original log line
        """
        pass

    @staticmethod
    def safe_parse_date(date_str: str, fmt: str) -> datetime | None:
        try:
            dt = datetime.strptime(date_str, fmt)
            # auth.log has no year — assume current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            return None
