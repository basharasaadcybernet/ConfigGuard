"""Secret-free public errors for configuration ingestion and parsing."""

from __future__ import annotations

from enum import StrEnum


class InputErrorCode(StrEnum):
    """Stable categories for rejected configuration input."""

    INVALID_PATH = "invalid_path"
    READ_ERROR = "read_error"
    FILE_TOO_LARGE = "file_too_large"
    EMPTY_INPUT = "empty_input"
    BINARY_INPUT = "binary_input"
    UNSUPPORTED_ENCODING = "unsupported_encoding"


class ConfigurationInputError(ValueError):
    """An ingestion failure whose string and repr contain no path or content."""

    def __init__(self, code: InputErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class ConfigurationParseError(ValueError):
    """Base class for safe parser rejection errors."""

    code = "parse_error"


class UnsupportedPlatformError(ConfigurationParseError):
    """The source has a clearly unsupported or non-compatible syntax."""

    code = "unsupported_platform"


class MalformedConfigurationError(ConfigurationParseError):
    """The source cannot safely be interpreted as a configuration."""

    code = "malformed_configuration"
