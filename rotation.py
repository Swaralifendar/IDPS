"""
Size-based rotation for the JSON Lines files, and a reader that
follows a file across rotations.

Writer side
-----------
    rotate_if_needed(path)

Before appending, a writer calls this. When the file reached its
size limit it is renamed:

    correlation.json -> correlation.1.json -> correlation.2.json ...

(event.json and NIDS alerts.json are NOT rotated: all data is kept.)

Each file has exactly one writer process, and writers open the
file for every write, so the rename works on Windows. If the file
is momentarily open elsewhere the rename fails silently and is
retried on the next write.

Reader side
-----------
    JsonlTail(path, checkpoint_path)

Reads complete new lines from a byte offset. The checkpoint stores
the offset AND the file's identity (NTFS file ID, kept across a
rename). When the identity changes, the reader first finishes the
rotated file it was reading, then starts the new file at offset 0,
so no line is lost or read twice. A line still being written
(no trailing newline) is left for the next read.
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple


MB = 1024 * 1024

# file name -> (max bytes, rotated files kept)
ROTATION_LIMITS = {
    "correlation.json": (100 * MB, 5),
    "ips_alerts.json": (50 * MB, 10),
    "ips_inline_blocks.json": (20 * MB, 10),
}

DEFAULT_LIMIT = (50 * MB, 5)

# Upper bound of lines returned by one JsonlTail.read_lines() call,
# so a large backlog is processed in chunks.
MAX_LINES_PER_READ = 5000


def rotated_path(path: Path, index: int) -> Path:
    """alerts.json, 2 -> alerts.2.json"""
    return path.with_name(f"{path.stem}.{index}{path.suffix}")


def rotate_if_needed(path, max_bytes: Optional[int] = None, backups: Optional[int] = None) -> bool:
    """
    Rotate `path` if it reached its size limit. Returns True if it
    was rotated. Never raises.
    """

    path = Path(path)
    default_max, default_backups = ROTATION_LIMITS.get(path.name, DEFAULT_LIMIT)
    max_bytes = max_bytes or default_max
    backups = backups or default_backups

    try:
        if not path.exists() or path.stat().st_size < max_bytes:
            return False

        oldest = rotated_path(path, backups)
        if oldest.exists():
            oldest.unlink()

        for index in range(backups - 1, 0, -1):
            source = rotated_path(path, index)
            if source.exists():
                source.replace(rotated_path(path, index + 1))

        path.replace(rotated_path(path, 1))
        return True

    except OSError:
        # File in use or permission problem: retry on next write.
        return False


def _file_id(path: Path) -> Optional[int]:
    try:
        return path.stat().st_ino or None
    except OSError:
        return None


class JsonlTail:
    """Follow a JSON Lines file across rotations (see module doc)."""

    def __init__(self, path, checkpoint_path, legacy_offset_loader=None):
        self.path = Path(path)
        self.checkpoint_path = Path(checkpoint_path)

        # Optional callable(dict) -> offset, for converting an older
        # checkpoint format (e.g. line numbers) to a byte offset.
        self.legacy_offset_loader = legacy_offset_loader

        self.offset, self.file_id = self._load_checkpoint()
        self._saved = (self.offset, self.file_id)

    # --------------------------------------------------------
    # Checkpoint
    # --------------------------------------------------------

    def _load_checkpoint(self) -> Tuple[int, Optional[int]]:
        if not self.checkpoint_path.exists():
            return 0, None

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "offset" in data:
                return int(data["offset"]), data.get("file_id")

            if self.legacy_offset_loader is not None:
                return int(self.legacy_offset_loader(data)), None

        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

        return 0, None

    def commit(self) -> None:
        """Save the current position (atomically) if it changed."""

        if (self.offset, self.file_id) == self._saved:
            return

        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.checkpoint_path.with_suffix(".tmp")

            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump({"offset": self.offset, "file_id": self.file_id}, f)

            temp_path.replace(self.checkpoint_path)
            self._saved = (self.offset, self.file_id)

        except OSError as e:
            print(f"[IDSIPS] Cannot save checkpoint {self.checkpoint_path}: {e}")

    # --------------------------------------------------------
    # Reading
    # --------------------------------------------------------

    def _find_rotated(self, file_id: int) -> Optional[int]:
        """Index of the rotated file that has the given file ID."""

        for index in range(1, 50):
            candidate = rotated_path(self.path, index)

            if not candidate.exists():
                break

            if _file_id(candidate) == file_id:
                return index

        return None

    @staticmethod
    def _read_from(path: Path, offset: int, limit: int, include_partial: bool):
        """
        Read complete lines from `offset`. Returns (lines, new_offset,
        reached_end). A trailing line without newline is only returned
        when include_partial is True (rotated files are finished).
        """

        lines = []
        reached_end = False

        with open(path, "rb") as f:
            f.seek(offset)

            while len(lines) < limit:
                raw = f.readline()

                if not raw:
                    reached_end = True
                    break

                if not raw.endswith(b"\n") and not include_partial:
                    reached_end = True
                    break

                offset += len(raw)
                text = raw.decode("utf-8", errors="replace").strip()

                if text:
                    lines.append(text)

        return lines, offset, reached_end

    def read_lines(self) -> List[str]:
        """
        Return complete new lines (stripped, non-empty). Call
        commit() afterwards to save the position.
        """

        lines: List[str] = []

        try:
            # Walk forward through the files until the current one:
            # the file being read may have been rotated several
            # times (alerts.json -> .1 -> .2) while we were idle.
            while len(lines) < MAX_LINES_PER_READ:
                current_id = _file_id(self.path) if self.path.exists() else None

                # Older checkpoint without file identity (or a
                # finished rotated file): continue with the current
                # file at the saved offset.
                if self.file_id is None:
                    if current_id is None:
                        break
                    self.file_id = current_id

                # --------------------------------------------
                # Reading the current file
                # --------------------------------------------
                if self.file_id == current_id:
                    # Same file, but truncated
                    if self.path.stat().st_size < self.offset:
                        self.offset = 0

                    new_lines, self.offset, _ = self._read_from(
                        self.path, self.offset,
                        MAX_LINES_PER_READ - len(lines), include_partial=False
                    )
                    lines.extend(new_lines)
                    break

                # --------------------------------------------
                # Our file was rotated: finish it, then move to
                # the next newer file
                # --------------------------------------------
                index = self._find_rotated(self.file_id)

                if index is None:
                    print(f"[IDSIPS] Rotated file for {self.path.name} not found; "
                          f"continuing with the current file")
                    self.file_id, self.offset = current_id, 0
                    if current_id is None:
                        break
                    continue

                old_lines, self.offset, done = self._read_from(
                    rotated_path(self.path, index), self.offset,
                    MAX_LINES_PER_READ - len(lines), include_partial=True
                )
                lines.extend(old_lines)

                if not done:
                    break

                self.offset = 0

                if index > 1:
                    self.file_id = _file_id(rotated_path(self.path, index - 1))
                else:
                    # Next is the current file (or it is not created
                    # yet: pick it up at offset 0 when it appears)
                    self.file_id = current_id

        except OSError as e:
            print(f"[IDSIPS] Cannot read {self.path}: {e}")

        return lines
