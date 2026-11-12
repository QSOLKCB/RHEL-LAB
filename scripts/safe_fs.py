"""Pinned, no-follow directory helpers for local-only research storage."""
from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
FILE_RDWR_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class UnsafePath(ValueError):
    """A path crosses an untrusted or ambiguous filesystem boundary."""


def absolute(path: str | Path) -> Path:
    path = Path(path)
    if ".." in path.parts:
        raise UnsafePath("parent traversal is forbidden")
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _trusted(directory_stat: os.stat_result) -> None:
    owner = directory_stat.st_uid
    mode = directory_stat.st_mode
    if owner not in (0, os.geteuid()):
        raise UnsafePath("directory ancestor belongs to another user")
    if mode & 0o022:
        # Root-owned sticky directories such as /tmp prevent other users
        # from renaming operator-owned child entries.
        if not (owner == 0 and mode & stat.S_ISVTX):
            raise UnsafePath("directory ancestor is group/other writable")


@contextmanager
def directory(path: str | Path, *, trusted: bool = True,
              private: bool = False, forbidden: tuple[int, int] | None = None):
    """Open every path component with O_NOFOLLOW; pin the final directory FD."""
    p = absolute(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        if trusted:
            _trusted(os.fstat(fd))
        for component in p.parts[1:]:
            next_fd = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if trusted:
                _trusted(info)
            if forbidden is not None and (info.st_dev, info.st_ino) == forbidden:
                raise UnsafePath("manifest destination is within evidence root")
        info = os.fstat(fd)
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise UnsafePath("directory must be operator-owned and private (0700)")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def lab_directory(path: str | Path, *, create: bool = False):
    """Pin an operator-owned private lab root with an opened trusted parent."""
    p = absolute(path)
    if p.name in ("", ".", ".."):
        raise UnsafePath("invalid lab root")
    with directory(p.parent) as parent_fd:
        if create:
            try:
                os.mkdir(p.name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass  # verify existing directory instead of trusting pathname
        fd = os.open(p.name, DIR_FLAGS, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise UnsafePath("lab root must be operator-owned and private")
            yield fd
        finally:
            os.close(fd)


@contextmanager
def private_child_directory(parent_fd: int, name: str, *, create: bool = False):
    if name in ("", ".", "..") or "/" in name:
        raise UnsafePath("invalid child directory name")
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise UnsafePath("child directory must be operator-owned and private")
        yield fd
    finally:
        os.close(fd)


def exists_at(fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def regular_at(parent_fd: int, name: str) -> int:
    fd = os.open(name, FILE_READ_FLAGS, dir_fd=parent_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise UnsafePath("only regular file inputs are supported")
    return fd
