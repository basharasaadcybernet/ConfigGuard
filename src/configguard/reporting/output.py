"""Safe, explicit, atomic report-file output."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path


class OutputWriteError(ValueError):
    """A safe public report-output failure."""


def write_new_report(path_value: str | os.PathLike[str], content: str) -> None:
    """Write UTF-8 content without directories, overwrite, or partial target files."""

    target = Path(path_value)
    parent = target.parent
    if not target.name or not parent.is_dir():
        raise OutputWriteError("The selected report destination is invalid.")
    if target.exists() or target.is_symlink():
        raise OutputWriteError("The selected report already exists; it was not overwritten.")

    temporary: Path | None = None
    try:
        descriptor, temporary_text = tempfile.mkstemp(
            prefix=".configguard-",
            suffix=".tmp",
            dir=parent,
        )
        temporary = Path(temporary_text)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target)
    except FileExistsError:
        raise OutputWriteError(
            "The selected report already exists; it was not overwritten."
        ) from None
    except (OSError, UnicodeError):
        raise OutputWriteError("The report could not be written safely.") from None
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
