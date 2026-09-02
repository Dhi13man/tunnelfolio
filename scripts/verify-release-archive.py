#!/usr/bin/env python3
import sys
import tarfile
from pathlib import Path, PurePosixPath


MAX_MEMBERS = 4_096
MAX_MEMBER_SIZE = 64 * 1024 * 1024
MAX_TOTAL_SIZE = 128 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 5:
        fail(f"usage: {sys.argv[0]} <archive> <root> <source-date-epoch> <destination>")

    archive = Path(sys.argv[1])
    root = sys.argv[2]
    source_date_epoch = int(sys.argv[3])
    destination = Path(sys.argv[4])
    if archive.name != f"{root}.tar.gz" or not destination.is_dir() or any(destination.iterdir()):
        fail("archive identity or extraction destination is invalid")

    required = {
        root: ("directory", 0o755),
        f"{root}/LICENSE": ("file", 0o644),
        f"{root}/README.md": ("file", 0o644),
        f"{root}/THIRD_PARTY_LICENSES": ("directory", 0o755),
        f"{root}/install.sh": ("file", 0o755),
        f"{root}/tunnelfolio": ("file", 0o755),
        f"{root}/tunnelfolio.service": ("file", 0o644),
        f"{root}/tunnelfolio.tmpfiles.conf": ("file", 0o644),
    }
    seen: set[str] = set()
    total_size = 0
    license_files = 0

    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > MAX_MEMBERS:
            fail("archive has too many members")

        for member in members:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            if (
                not name
                or path.is_absolute()
                or str(path) != name
                or any(part in ("", ".", "..") for part in path.parts)
                or name in seen
            ):
                fail(f"unsafe or duplicate archive member: {member.name!r}")
            seen.add(name)

            if member.issparse() or not (member.isdir() or member.isfile()):
                fail(f"unsupported archive member type: {name}")
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                fail(f"invalid archive ownership metadata: {name}")
            if member.mtime != source_date_epoch:
                fail(f"invalid archive timestamp: {name}")
            kind = "directory" if member.isdir() else "file"
            mode = member.mode & 0o7777
            total_size += member.size
            if member.size > MAX_MEMBER_SIZE or total_size > MAX_TOTAL_SIZE:
                fail("archive expansion limit exceeded")

            if name in required:
                if (kind, mode) != required[name]:
                    fail(f"invalid type or mode for archive member: {name}")
                continue

            prefix = f"{root}/THIRD_PARTY_LICENSES/"
            if not name.startswith(prefix):
                fail(f"unexpected archive member: {name}")
            if kind == "directory":
                if mode != 0o755:
                    fail(f"invalid license directory mode: {name}")
                continue
            if path.name not in {"LICENSE", "LICENSE.md", "NOTICE"} or mode not in {0o444, 0o644}:
                fail(f"invalid license file: {name}")
            if member.size == 0:
                fail(f"empty license file: {name}")
            license_files += 1

        missing = required.keys() - seen
        if missing:
            fail(f"archive is missing required members: {', '.join(sorted(missing))}")
        if license_files == 0:
            fail("archive contains no third-party license files")

        bundle.extractall(destination, members=members, filter="data")

    for path in destination.rglob("*"):
        if path.is_symlink():
            fail(f"extracted symlink is forbidden: {path}")


if __name__ == "__main__":
    main()
