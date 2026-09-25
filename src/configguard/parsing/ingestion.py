"""Bounded, read-only ingestion for explicitly selected local files."""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path

from configguard.parsing.contracts import ConfigurationSource
from configguard.parsing.errors import ConfigurationInputError, InputErrorCode

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_ALLOWED_CONTROL_CHARACTERS = {"\t", "\n", "\r"}


class ConfigurationIngestor:
    """Read a local file once, within a strict byte budget, without persistence."""

    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self._max_bytes = max_bytes

    @property
    def max_bytes(self) -> int:
        """Return the configured maximum number of input bytes."""

        return self._max_bytes

    def read(self, path_value: str | os.PathLike[str]) -> ConfigurationSource:
        """Return validated UTF-8 text from an explicit local path.

        Errors intentionally omit the absolute path and source content.
        """

        path_text = os.fspath(path_value)
        if path_text.startswith(("\\\\", "//")):
            raise ConfigurationInputError(
                InputErrorCode.INVALID_PATH,
                "The selected configuration must be a local regular file.",
            )

        path = Path(path_text)
        if path.is_symlink():
            raise ConfigurationInputError(
                InputErrorCode.INVALID_PATH,
                "Symbolic links are not accepted as configuration input.",
            )

        try:
            size = path.stat().st_size
        except OSError:
            raise ConfigurationInputError(
                InputErrorCode.READ_ERROR,
                "The selected configuration could not be read.",
            ) from None

        if not path.is_file():
            raise ConfigurationInputError(
                InputErrorCode.INVALID_PATH,
                "The selected configuration must be a local regular file.",
            )
        if size > self._max_bytes:
            raise ConfigurationInputError(
                InputErrorCode.FILE_TOO_LARGE,
                "The selected configuration exceeds the configured size limit.",
            )

        try:
            with path.open("rb") as stream:
                data = stream.read(self._max_bytes + 1)
        except OSError:
            raise ConfigurationInputError(
                InputErrorCode.READ_ERROR,
                "The selected configuration could not be read.",
            ) from None

        if len(data) > self._max_bytes:
            raise ConfigurationInputError(
                InputErrorCode.FILE_TOO_LARGE,
                "The selected configuration exceeds the configured size limit.",
            )

        return self.read_bytes(path.name, data)

    def read_bytes(self, label: str, data: bytes) -> ConfigurationSource:
        """Return validated UTF-8 text from an ephemeral in-memory byte payload."""

        if len(data) > self._max_bytes:
            raise ConfigurationInputError(
                InputErrorCode.FILE_TOO_LARGE,
                "The selected configuration exceeds the configured size limit.",
            )

        try:
            text = data.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError:
            raise ConfigurationInputError(
                InputErrorCode.UNSUPPORTED_ENCODING,
                "The selected configuration is not valid UTF-8 text.",
            ) from None

        if not text.strip():
            raise ConfigurationInputError(
                InputErrorCode.EMPTY_INPUT,
                "The selected configuration is empty.",
            )
        if _contains_binary_controls(text):
            raise ConfigurationInputError(
                InputErrorCode.BINARY_INPUT,
                "The selected configuration contains binary control data.",
            )

        return ConfigurationSource(label=_safe_label(_basename(label)), text=text)


def _contains_binary_controls(text: str) -> bool:
    return any(
        character not in _ALLOWED_CONTROL_CHARACTERS and unicodedata.category(character) == "Cc"
        for character in text
    )


def _safe_label(name: str) -> str:
    cleaned = "".join(
        character if character.isprintable() and character not in "\r\n\t" else "_"
        for character in name
    )
    return (cleaned or "configuration")[:128]


def _basename(label: str) -> str:
    return label.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
