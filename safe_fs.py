from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable

from models import FileRecord, Inventory, ScanConfig, SkippedFile


class SafeFSError(ValueError):
    pass


class SafeFS:
    """Read-only filesystem helper constrained to a canonical root."""

    def __init__(self, root: str | os.PathLike[str], config: ScanConfig | None = None):
        self.root = Path(root).expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise SafeFSError(f"root is not a directory: {self.root}")
        self.config = config or ScanConfig()

    def resolve_under_root(self, candidate: str | os.PathLike[str]) -> Path:
        path = Path(candidate)
        if not path.is_absolute():
            path = self.root / path
        resolved = path.resolve(strict=False)
        if not self._is_under_root(resolved):
            raise SafeFSError(f"path escapes root: {candidate}")
        return resolved

    def relative(self, path: str | os.PathLike[str]) -> str:
        resolved = Path(path).resolve(strict=False)
        if not self._is_under_root(resolved):
            raise SafeFSError(f"path escapes root: {path}")
        return resolved.relative_to(self.root).as_posix()

    def inventory(self) -> Inventory:
        result = Inventory()
        files_seen = 0
        total_bytes = 0

        for dirpath, dirnames, filenames in os.walk(self.root, topdown=True, followlinks=False):
            current_dir = Path(dirpath)
            kept_dirs: list[str] = []
            for dirname in sorted(dirnames):
                child = current_dir / dirname
                rel = self._safe_rel_for_report(child)
                if dirname in self.config.skip_dir_names:
                    result.skipped.append(SkippedFile(rel, "skipped_directory"))
                    continue
                if child.is_symlink():
                    try:
                        resolved = child.resolve(strict=True)
                    except OSError:
                        result.skipped.append(SkippedFile(rel, "broken_symlink"))
                        continue
                    if not self._is_under_root(resolved):
                        result.skipped.append(SkippedFile(rel, "symlink_escape"))
                        continue
                    result.skipped.append(SkippedFile(rel, "symlink_directory"))
                    continue
                kept_dirs.append(dirname)
            dirnames[:] = kept_dirs

            for filename in sorted(filenames):
                child = current_dir / filename
                rel = self._safe_rel_for_report(child)
                try:
                    lst = child.lstat()
                except OSError as exc:
                    result.skipped.append(SkippedFile(rel, f"stat_error:{exc.__class__.__name__}"))
                    continue

                if stat.S_ISLNK(lst.st_mode):
                    try:
                        resolved = child.resolve(strict=True)
                    except OSError:
                        result.skipped.append(SkippedFile(rel, "broken_symlink"))
                        continue
                    if not self._is_under_root(resolved):
                        result.skipped.append(SkippedFile(rel, "symlink_escape"))
                        continue
                    try:
                        st = resolved.stat()
                    except OSError as exc:
                        result.skipped.append(SkippedFile(rel, f"stat_error:{exc.__class__.__name__}"))
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        result.skipped.append(SkippedFile(rel, "special_file"))
                        continue
                    size = st.st_size
                    is_symlink = True
                else:
                    if not stat.S_ISREG(lst.st_mode):
                        result.skipped.append(SkippedFile(rel, "special_file"))
                        continue
                    size = lst.st_size
                    is_symlink = False

                files_seen += 1
                if files_seen > self.config.max_files:
                    result.skipped.append(SkippedFile(rel, "max_files_exceeded"))
                    continue
                if total_bytes + size > self.config.max_total_bytes:
                    result.skipped.append(SkippedFile(rel, "max_total_bytes_exceeded"))
                    continue
                total_bytes += size
                result.files.append(FileRecord(str(child), rel, size, is_symlink))

        return result

    def read_bytes_limited(self, record: FileRecord, limit: int) -> bytes:
        path = self.resolve_under_root(record.path)
        with path.open("rb") as handle:
            return handle.read(limit)

    def _is_under_root(self, path: Path) -> bool:
        try:
            path.relative_to(self.root)
            return True
        except ValueError:
            return False

    def _safe_rel_for_report(self, path: Path) -> str:
        try:
            return path.resolve(strict=False).relative_to(self.root).as_posix()
        except ValueError:
            try:
                return path.relative_to(self.root).as_posix()
            except ValueError:
                return path.name


def prioritize_files(files: Iterable[FileRecord]) -> list[FileRecord]:
    return sorted(files, key=lambda f: (-path_priority(f.relative_path), f.relative_path))


def path_priority(relative_path: str) -> int:
    lower = relative_path.lower()
    score = 0
    weighted_signals = {
        ".env": 45,
        "credentials": 45,
        "secret": 40,
        "token": 36,
        "password": 36,
        "passwd": 34,
        "id_rsa": 60,
        "id_ed25519": 60,
        ".ssh/": 45,
        ".aws/": 45,
        ".azure/": 36,
        ".gcp/": 36,
        "kubeconfig": 35,
        ".kube/": 35,
        "docker/config": 32,
        ".docker/": 32,
        ".npmrc": 30,
        ".pypirc": 30,
        ".netrc": 32,
        "history": 20,
        ".bashrc": 42,
        ".zshrc": 42,
        ".profile": 36,
        ".bash_profile": 36,
        "profile.d/": 30,
        ".envrc": 36,
        ".config/": 12,
        "config": 18,
        "connection": 16,
        "database": 16,
        ".yaml": 6,
        ".yml": 6,
        ".json": 6,
        ".ini": 5,
        ".cfg": 5,
        ".toml": 5,
        ".env.": 30,
    }
    normalized = lower.replace("\\", "/")
    for signal, weight in weighted_signals.items():
        if signal in normalized:
            score += weight
    return score
