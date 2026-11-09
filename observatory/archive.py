"""Write-once, content-addressed raw artifact store."""
import hashlib
import os
import stat
from pathlib import Path

from . import config


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact_path(sha: str, root: Path | None = None) -> Path:
    root = root or config.ARCHIVE_DIR
    return root / sha[:2] / sha[2:4] / sha


def store(data: bytes, root: Path | None = None) -> tuple[str, Path, bool]:
    """Store bytes under their SHA-256. Never overwrites. Returns (sha, path, newly_written)."""
    sha = sha256_hex(data)
    path = artifact_path(sha, root)
    if path.exists():
        return sha, path, False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.link(tmp, path)  # atomic create-if-absent; fails rather than overwrite
    except FileExistsError:
        pass
    except OSError:
        if not path.exists():
            os.replace(tmp, path)
    if tmp.exists():
        tmp.unlink()
    os.chmod(path, stat.S_IREAD)  # read-only at the filesystem level
    return sha, path, True


def store_timed(data: bytes, root: Path | None = None) -> dict:
    """store() plus the distinct times the addendum requires: hash calculation, write start/complete,
    and a post-write read-back verification (4.4)."""
    from .db import now_utc
    sha = sha256_hex(data)
    hash_utc = now_utc()
    write_started = now_utc()
    _, path, new = store(data, root)
    write_completed = now_utc()
    verified = sha256_hex(path.read_bytes()) == sha
    return dict(sha=sha, path=path, newly_written=new, hash_calculated_utc=hash_utc,
                write_started_utc=write_started, write_completed_utc=write_completed, post_write_verified=verified)


def read(sha: str, root: Path | None = None) -> bytes:
    return artifact_path(sha, root).read_bytes()


def verify(sha: str, root: Path | None = None) -> bool:
    p = artifact_path(sha, root)
    return p.exists() and sha256_hex(p.read_bytes()) == sha
