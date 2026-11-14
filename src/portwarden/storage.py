"""Safe local file handling for inventories and baselines.

Baseline files describe the exposed services of real devices, so they
are treated as security-sensitive local data: reads are size-limited
and strictly decoded, and writes are atomic with restrictive
permissions so an interrupted process can never leave a half-written
baseline behind.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import InventoryError

#: Hard ceiling for inventory files. Inventories are lists of ports, not
#: logs; anything near this size is almost certainly an attack or a mistake.
MAX_INVENTORY_BYTES = 64 * 1024 * 1024

_BASELINE_MODE = 0o600


def load_json_document(path: str | Path, *, max_bytes: int = MAX_INVENTORY_BYTES) -> Any:
    """Read one UTF-8 JSON document, enforcing a size ceiling first.

    Raises:
        OSError: if the file cannot be read.
        InventoryError: if the file is too large, not valid UTF-8, or not
            exactly one JSON document.
    """
    target = Path(path)
    size = target.stat().st_size
    if size > max_bytes:
        raise InventoryError(f"inventory file is {size} bytes; the limit is {max_bytes}")
    with target.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InventoryError(f"inventory file exceeds the {max_bytes}-byte read limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError(f"inventory is not valid UTF-8: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InventoryError(f"invalid JSON: {exc}") from exc


def atomic_write_bytes(path: str | Path, data: bytes, *, mode: int = _BASELINE_MODE) -> None:
    """Write bytes so readers only ever see the old or the new file.

    The payload lands in a temporary file in the destination directory,
    is flushed and fsynced, gets its final permissions, and is then
    renamed over the target. The temporary file is removed on any
    failure.
    """
    target = Path(path)
    directory = target.parent if str(target.parent) else Path()
    if not directory.is_dir():
        raise InventoryError(f"destination directory does not exist: {directory}")
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".portwarden-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).chmod(mode)
        Path(temporary).replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()
        raise
    try:  # best effort: make the rename itself durable
        directory_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def serialize_document(document: dict[str, Any]) -> bytes:
    """Serialize a JSON document deterministically with a trailing newline."""
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)
    return (text + "\n").encode("utf-8")


def write_baseline(path: str | Path, document: dict[str, Any], *, overwrite: bool) -> None:
    """Atomically write a baseline after confirming replacement.

    Raises:
        InventoryError: if the destination exists and ``overwrite`` is
            False. Replacing an accepted baseline is always an explicit
            operator decision.
    """
    target = Path(path)
    if target.exists() and not overwrite:
        raise InventoryError(
            f"refusing to overwrite existing baseline {target}; pass --force to replace it"
        )
    atomic_write_bytes(target, serialize_document(document))
