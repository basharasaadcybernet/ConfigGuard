"""Secure, bounded file-ingestion tests using synthetic content only."""

from __future__ import annotations

from pathlib import Path

import pytest

from configguard.parsing import (
    ConfigurationIngestor,
    ConfigurationInputError,
    InputErrorCode,
)


def test_reads_utf8_with_optional_bom_without_persisting_copy(tmp_path: Path) -> None:
    source_path = tmp_path / "synthetic-router.txt"
    source_path.write_bytes(b"\xef\xbb\xbfversion 15.7\nhostname TEST-RTR\n")

    ingestor = ConfigurationIngestor()
    source = ingestor.read(source_path)

    assert ingestor.max_bytes == 2 * 1024 * 1024
    assert source.label == "synthetic-router.txt"
    assert source.text.startswith("version 15.7")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["synthetic-router.txt"]


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        (b"version 15.7\x00hostname TEST", InputErrorCode.BINARY_INPUT),
        (b"version 15.7\xff", InputErrorCode.UNSUPPORTED_ENCODING),
        (b"\n\t\r", InputErrorCode.EMPTY_INPUT),
    ],
)
def test_rejects_binary_unsupported_and_empty_input(
    tmp_path: Path,
    payload: bytes,
    expected_code: InputErrorCode,
) -> None:
    source_path = tmp_path / "synthetic-input.txt"
    source_path.write_bytes(payload)

    with pytest.raises(ConfigurationInputError) as caught:
        ConfigurationIngestor().read(source_path)

    assert caught.value.code is expected_code
    assert payload.decode("utf-8", errors="ignore") not in str(caught.value)


def test_rejects_oversized_input_with_bounded_read(tmp_path: Path) -> None:
    source_path = tmp_path / "synthetic-large.txt"
    source_path.write_bytes(b"hostname TEST\n" * 10)

    with pytest.raises(ConfigurationInputError) as caught:
        ConfigurationIngestor(max_bytes=32).read(source_path)

    assert caught.value.code is InputErrorCode.FILE_TOO_LARGE


def test_public_read_error_omits_absolute_private_path(tmp_path: Path) -> None:
    missing = tmp_path / "private" / "SYNTHETIC-SECRET-NAME.txt"

    with pytest.raises(ConfigurationInputError) as caught:
        ConfigurationIngestor().read(missing)

    public_error = f"{caught.value!s} {caught.value!r}"
    assert str(missing) not in public_error
    assert "SYNTHETIC-SECRET-NAME" not in public_error


def test_source_repr_hides_configuration_text(tmp_path: Path) -> None:
    source_path = tmp_path / "synthetic.txt"
    source_path.write_text(
        "version 15.7\nusername user secret SYNTHETIC-DO-NOT-REPR\n",
        encoding="utf-8",
    )

    source = ConfigurationIngestor().read(source_path)

    assert "SYNTHETIC-DO-NOT-REPR" not in repr(source)
