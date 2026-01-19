"""Base parser interface for detection rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ParsedRule:
    """Intermediate representation of a parsed detection rule.

    This is the output contract for all parsers before normalization.
    """

    # Source information
    source: str  # sigma, elastic, splunk
    file_path: str
    raw_content: str

    # Core fields (required)
    title: str
    detection_logic_raw: Any  # Vendor-specific detection logic

    # Optional metadata
    description: Optional[str] = None
    author: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None

    # Classification (vendor-specific, to be normalized)
    log_source: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    # MITRE ATT&CK (may be in tags or dedicated fields)
    mitre_attack: dict = field(default_factory=dict)

    # False positives / known limitations
    false_positives: list[str] = field(default_factory=list)

    # Additional vendor-specific fields
    extra: dict = field(default_factory=dict)


class BaseParser(ABC):
    """Abstract base class for detection rule parsers."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Return the source name for this parser (e.g., 'sigma', 'elastic')."""
        pass

    @abstractmethod
    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a detection rule file and return structured data.

        Args:
            file_path: Path to the rule file (relative to repo root)
            content: Raw file content

        Returns:
            ParsedRule if successful, None if parsing fails
        """
        pass

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file.

        Args:
            file_path: Path to check

        Returns:
            True if this parser handles this file type
        """
        pass

    def _safe_get(self, data: dict, *keys: str, default: Any = None) -> Any:
        """Safely get nested dictionary values.

        Args:
            data: Dictionary to traverse
            *keys: Keys to traverse
            default: Default value if key not found

        Returns:
            Value at the nested key path, or default
        """
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                return default
        return current
