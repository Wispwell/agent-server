"""Append-only hash-chained log. M0.

    h_n = SHA-256(canonical(entry_n) || h_(n-1))

Tamper-**evident**, not tamper-proof: nothing here stops someone editing the
file, it makes the edit undeniable. Altering any entry invalidates every hash
after it, and deleting one from the middle breaks the sequence.

One limit, stated plainly: **truncating the tail is not detectable from the
file alone.** A chain cut short is still internally consistent, and a process
that starts fresh has nothing to compare against. A live Ledger catches it,
because it remembers the head it wrote. Detecting it across a restart needs an
anchor kept outside the file — a signed checkpoint, or the head hash published
somewhere else. Neither is in v0; the property claimed here is exactly
"alteration and interior deletion are evident", no more.

Stored as JSON Lines so it can be read incrementally, appended to without
rewriting, and inspected with ordinary tools. Every append is fsync'd: an audit
record of a denial that a crash could lose is not an audit record.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..crypto.canonical import canonicalize
from .events import EventType

__all__ = ["GENESIS_HASH", "Ledger", "LedgerCorruption"]

GENESIS_HASH = "0" * 64


class LedgerCorruption(Exception):
    """The chain does not verify. Includes the sequence number that broke it."""

    def __init__(self, message: str, seq: int | None = None):
        super().__init__(message)
        self.seq = seq


def _entry_hash(entry: dict[str, Any], previous: str) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(canonicalize(body) + previous.encode("ascii")).hexdigest()


class Ledger:
    """An append-only chain of events on disk.

    Not thread-safe by itself; the containment server serialises writes, which
    it must do anyway to keep evaluate-then-record atomic.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._resume()

    # -- state ------------------------------------------------------------

    def _resume(self) -> tuple[int, str]:
        """Recover sequence and head hash from an existing file."""
        if not self.path.exists():
            return -1, GENESIS_HASH
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return -1, GENESIS_HASH
        entry = json.loads(last)
        return entry["seq"], entry["hash"]

    @property
    def head(self) -> str:
        """Hash of the most recent entry, or GENESIS_HASH if empty."""
        return self._head

    def __len__(self) -> int:
        return self._seq + 1

    # -- writing ----------------------------------------------------------

    def append(
        self,
        event: EventType | str,
        data: dict[str, Any] | None = None,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Append one event and return the entry as written."""
        entry: dict[str, Any] = {
            "seq": self._seq + 1,
            "ts": int(time.time()) if now is None else int(now),
            "type": str(event),
            "prev": self._head,
            "data": data or {},
        }
        entry["hash"] = _entry_hash(entry, self._head)

        line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        self._seq = entry["seq"]
        self._head = entry["hash"]
        return entry

    # -- reading ----------------------------------------------------------

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def read(self) -> list[dict[str, Any]]:
        return list(self)

    # -- verification -----------------------------------------------------

    def verify(self) -> int:
        """Recompute the whole chain. Returns the entry count, or raises.

        Checks three things: that each entry's hash is the hash of its own
        content, that `prev` matches the previous entry's hash, and that
        sequence numbers are contiguous from zero — the last of which is what
        catches a file truncated to a shorter but internally consistent chain.
        """
        previous = GENESIS_HASH
        count = 0
        for expected_seq, entry in enumerate(self):
            seq = entry.get("seq")
            if seq != expected_seq:
                raise LedgerCorruption(
                    f"sequence break: expected {expected_seq}, found {seq}", seq
                )
            if entry.get("prev") != previous:
                raise LedgerCorruption(f"broken link at seq {seq}", seq)
            recomputed = _entry_hash(entry, previous)
            if entry.get("hash") != recomputed:
                raise LedgerCorruption(f"content altered at seq {seq}", seq)
            previous = entry["hash"]
            count += 1
        if count and previous != self._head:
            raise LedgerCorruption("head hash does not match the chain tail")
        return count
