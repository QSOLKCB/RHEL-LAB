#!/bin/bash
# QSOL-IMC RHEL-LAB: offline host state and before/after SHA-256 receipts.
# Run as an unprivileged user. NO sudo, installs, networking or VM actions.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec /usr/bin/python3 -I - "$@" <<'PYTHON'
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import resource
import secrets
import stat
import subprocess
import sys
import tempfile

SCHEMA = "qsol-rhel-host-preflight/v1"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_RECEIPT = 1024 * 1024

class Refusal(ValueError):
    pass

def canonical(path):
    path = pathlib.Path(path)
    if any(ord(character) < 32 or ord(character) == 127
           for character in os.fspath(path)):
        raise Refusal("control characters are forbidden in host paths")
    if ".." in path.parts:
        raise Refusal("parent traversal is forbidden")
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path
    return path

def check_dir(info):
    if info.st_uid not in (0, os.geteuid()):
        raise Refusal("foreign-owned receipt directory ancestor")
    if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
        raise Refusal("untrusted writable receipt ancestor")

def directory(path, create=False, private=False):
    path = canonical(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        check_dir(os.fstat(fd))
        for component in path.parts[1:]:
            try:
                child = os.open(component, DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=fd)
                child = os.open(component, DIR_FLAGS, dir_fd=fd)
            try:
                check_dir(os.fstat(child))
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise Refusal("receipt directory must be operator-owned and private (0700)")
        return fd
    except BaseException:
        os.close(fd)
        raise

def new_file(dir_fd, name, payload):
    if not re.fullmatch(r"[a-z0-9_.-]+", name) or len(payload) > MAX_RECEIPT:
        raise Refusal("invalid receipt name or size")
    fd = os.open(name, FILE_FLAGS, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise Refusal("short receipt write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(dir_fd)
    return hashlib.sha256(payload).hexdigest()

def seal(dir_fd, name, value):
    payload = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                          allow_nan=False) + "\n").encode("utf-8")
    digest = new_file(dir_fd, name, payload)
    new_file(dir_fd, name + ".sha256", f"{digest}  {name}\n".encode("ascii"))
    return digest

def read_regular(dir_fd, name, limit=MAX_RECEIPT):
    fd = os.open(name, READ_FLAGS, dir_fd=dir_fd)
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_uid != os.geteuid()
                or first.st_mode & 0o077 or first.st_size > limit):
            raise Refusal("unsafe receipt file ownership/type/mode/size")
        chunks = []
        length = 0
        while length <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        last = os.fstat(fd)
        ident = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                           s.st_mtime_ns, s.st_ctime_ns)
        if length > limit or length != first.st_size or ident(first) != ident(last):
            raise Refusal("receipt size or identity changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)

def checked(dir_fd, name):
    body = read_regular(dir_fd, name)
    digest = hashlib.sha256(body).hexdigest()
    line = read_regular(dir_fd, name + ".sha256", 256).decode("ascii")
    if line != f"{digest}  {name}\n":
        raise Refusal("receipt SHA-256 mismatch: " + name)
    value = json.loads(body)
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise Refusal("receipt schema invalid: " + name)
    return value, digest

def small_file(name, cap=131072):
    try:
        with open(name, "rb") as stream:
            value = stream.read(cap + 1)
        return value.decode("utf-8", "replace") if len(value) <= cap else ""
    except OSError:
        return ""

def binary(name):
    locations = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
    if name == "uv":
        home = pathlib.Path.home()
        locations += [str(home / ".local/bin"), str(home / ".cargo/bin")]
    for parent in locations:
        path = pathlib.Path(parent) / name
        try:
            if path.is_symlink():
                continue
            info = path.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022 or not os.access(path, os.X_OK)):
                continue
            fd = directory(path.parent)
            os.close(fd)
            return str(path)
        except (OSError, Refusal):
            pass
    return None

def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024, 128 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def run(name, *args, pass_fds=()):
    exe = binary(name)
    if exe is None:
        return {"status": "unavailable_or_untrusted"}
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
           "LANG": "C", "HOME": str(pathlib.Path.home()),
           "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0"}
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen([exe, *args], env=env,
                                       stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT,
                                       close_fds=True, pass_fds=pass_fds,
                                       preexec_fn=child_limits)
        except OSError as exc:
            return {"status": "launch_error", "type": type(exc).__name__}
        try:
            code = process.wait(timeout=5)
            timeout = False
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait()
            timeout = True
        output.seek(0)
        content = output.read(8193)
    return {"status": "timeout" if timeout else "executed", "exit_code": code,
            "truncated": len(content) > 8192,
            "output": content[:8192].decode("utf-8", "backslashreplace").strip()}

def os_release():
    fields = {}
    for line in small_file("/etc/os-release", 8192).splitlines():
        name, sep, value = line.partition("=")
        if sep and name in ("PRETTY_NAME", "ID", "VERSION_ID", "VERSION_CODENAME"):
            fields[name] = value.strip().strip('"')
    return fields

def cpu():
    text = small_file("/proc/cpuinfo", 1024 * 1024)
    model, flags = "", set()
    for line in text.splitlines():
        name, _, value = line.partition(":")
        if name.strip() == "model name" and not model:
            model = value.strip()[:256]
        if name.strip() in ("flags", "Features"):
            flags = set(value.split())
            break
    return {"logical_cpus": os.cpu_count(), "model": model,
            "virtualization_flags": sorted(flags & {"vmx", "svm"})}

def memory():
    result = {}
    for line in small_file("/proc/meminfo", 32768).splitlines():
        key, sep, value = line.partition(":")
        if sep and key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            match = re.search(r"(\d+)", value)
            if match:
                result[key + "_kib"] = int(match.group(1))
    return result

def filesystem(path):
    try:
        v = os.statvfs(path)
        return {"total_bytes": v.f_blocks * v.f_frsize,
                "available_bytes": v.f_bavail * v.f_frsize}
    except OSError as exc:
        return {"status": type(exc).__name__}

def dbx():
    try:
        files = sorted(pathlib.Path("/sys/firmware/efi/efivars").glob("dbx-*"))
        if not files:
            return {"status": "absent_or_unreadable"}
        if not stat.S_ISREG(files[0].lstat().st_mode):
            return {"status": "not_regular"}
        with files[0].open("rb") as stream:
            data = stream.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            return {"status": "too_large"}
        return {"status": "hashed", "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data)}
    except (OSError, ValueError) as exc:
        return {"status": "unavailable", "type": type(exc).__name__}

def kvm():
    try:
        info = os.stat("/dev/kvm", follow_symlinks=False)
        return {"present": True, "char_device": stat.S_ISCHR(info.st_mode),
                "read_write": os.access("/dev/kvm", os.R_OK | os.W_OK),
                "mode": oct(stat.S_IMODE(info.st_mode))}
    except OSError:
        return {"present": False, "char_device": False, "read_write": False}

def _git_text_at(parent_fd, name, limit=4096):
    """Read one pinned, no-follow Git metadata file; never run Git itself."""
    if "/" in name or name in ("", ".", ".."):
        raise Refusal("invalid Git metadata component")
    fd = os.open(name, READ_FLAGS, dir_fd=parent_fd)
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or
                first.st_uid not in (0, os.geteuid()) or
                first.st_mode & 0o022 or first.st_size > limit):
            raise Refusal("untrusted or oversized Git metadata")
        chunks = []
        count = 0
        while count <= limit:
            chunk = os.read(fd, min(4096, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            chunks.append(chunk)
        last = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                              s.st_mtime_ns, s.st_ctime_ns)
        if count > limit or count != first.st_size or identity(first) != identity(last):
            raise Refusal("Git metadata changed during inspection")
        return b"".join(chunks).decode("ascii").strip()
    finally:
        os.close(fd)


def _git_loose_ref(git_fd, ref):
    """Resolve a heads-only ref relative to pinned .git; refuse symlink paths."""
    parts = ref.split("/")
    if (parts[:2] != ["refs", "heads"] or
            len(parts) < 3 or
            any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", part)
                or part.endswith(".lock") or part in (".", "..")
                for part in parts)):
        raise Refusal("unsupported or unsafe Git symbolic ref")
    fd = os.dup(git_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            try:
                check_dir(os.fstat(child))
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return _git_text_at(fd, parts[-1])
    finally:
        os.close(fd)


def _git_packed_ref(git_fd, ref):
    packed = _git_text_at(git_fd, "packed-refs", 262144)
    for line in packed.splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        fields = line.split(" ")
        if len(fields) == 2 and fields[1] == ref:
            return fields[0]
    raise Refusal("Git HEAD ref not present in packed-refs")


def _git_head_sha(git_fd):
    """Read HEAD and its target from the pinned metadata directory, no filters."""
    head = _git_text_at(git_fd, "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", head):
        if _git_text_at(git_fd, "HEAD") != head:
            raise Refusal("Git detached HEAD changed during inspection")
        return head
    if not head.startswith("ref: "):
        raise Refusal("unsupported Git HEAD representation")
    ref = head[5:]
    try:
        sha = _git_loose_ref(git_fd, ref)
        packed = False
    except FileNotFoundError:
        sha = _git_packed_ref(git_fd, ref)
        packed = True
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Refusal("invalid or missing pinned Git ref")
    if _git_text_at(git_fd, "HEAD") != head:
        raise Refusal("Git HEAD changed while inspecting")
    second = _git_packed_ref(git_fd, ref) if packed else _git_loose_ref(git_fd, ref)
    if second != sha:
        raise Refusal("Git ref changed during inspection")
    return sha


def repo_state(path):
    """Report pinned HEAD only; never evaluate Git config, hooks, filters or diff."""
    if path is None:
        return {"status": "not_supplied"}
    folder = canonical(path)
    try:
        folder_fd = directory(folder)
    except (FileNotFoundError, NotADirectoryError, Refusal):
        return {"status": "not_found_or_untrusted"}
    try:
        try:
            git_fd = os.open(".git", DIR_FLAGS, dir_fd=folder_fd)
        except (OSError, ValueError):
            return {"status": "no_trusted_git_metadata"}
        try:
            check_dir(os.fstat(git_fd))
            sha = _git_head_sha(git_fd)
            # A metadata directory swapped after opening cannot redirect the
            # pinned reads and must not silently be reported as current.
            current = os.stat(".git", dir_fd=folder_fd, follow_symlinks=False)
            pinned = os.fstat(git_fd)
            if ((current.st_dev, current.st_ino) !=
                    (pinned.st_dev, pinned.st_ino)):
                raise Refusal("Git metadata directory rebound during inspection")
            return {"status": "identified", "head_sha": sha,
                    "tracked_changes": None,
                    "tracked_changes_status": "not_checked_to_avoid_git_execution"}
        except (OSError, ValueError):
            return {"status": "untrusted_or_unstable_git_metadata"}
        finally:
            os.close(git_fd)
    finally:
        os.close(folder_fd)

def capture(session, repo):
    uname = os.uname()
    cpu_modules = sorted({row.split()[0] for row in
                          small_file("/proc/modules", 262144).splitlines()
                          if row.split() and row.split()[0].startswith("kvm")})
    commands = {
        "uv": ("uv", "--version"),
        "git": ("git", "--version"),
        "qemu_img": ("qemu-img", "--version"),
        "qemu_system": ("qemu-system-x86_64", "--version"),
        "virsh": ("virsh", "--version"),
        "secure_boot": ("mokutil", "--sb-state"),
        "virt_detection": ("systemd-detect-virt",),
        "apparmor": ("aa-enabled",),
        "selinux": ("getenforce",),
    }
    packages = ("qemu-system-x86", "qemu-utils", "libvirt-clients",
                "libvirt-daemon-system", "libvirt-daemon-driver-qemu",
                "ovmf", "swtpm", "apparmor", "mokutil", "fwupd")
    return {
        "os": os_release(),
        "kernel": {"release": uname.release, "version": uname.version,
                   "architecture": uname.machine,
                   "boot_id": small_file("/proc/sys/kernel/random/boot_id", 128).strip()},
        "cpu": cpu(), "memory": memory(),
        "storage": {"home": filesystem(pathlib.Path.home()),
                    "receipt_filesystem": filesystem(session)},
        "firmware": {"uefi": pathlib.Path("/sys/firmware/efi").is_dir(),
                     "dbx": dbx()},
        "virtualization": {"kvm": kvm(), "kvm_modules": cpu_modules},
        "security": {
            "kernel_lockdown": small_file("/sys/kernel/security/lockdown", 1024).strip() or "unavailable",
            "apparmor_kernel": small_file("/sys/module/apparmor/parameters/enabled", 128).strip() or "unavailable"},
        "tools": {**{label: run(*args) for label, args in commands.items()},
                  "python": {"status": "running_interpreter",
                             "version": sys.version.split()[0]}},
        "packages": run("dpkg-query", "-W", *packages),
        "repository": repo_state(repo),
    }

def difference(before, after, lhs_sha, rhs_sha):
    def flatten(value, prefix=""):
        if not isinstance(value, dict):
            return {prefix: value}
        result = {}
        for key, child in sorted(value.items()):
            result.update(flatten(child, prefix + "." + key if prefix else key))
        return result
    lhs, rhs = flatten(before["system"]), flatten(after["system"])
    volatile = {"memory.MemAvailable_kib", "memory.SwapFree_kib",
                "storage.home.available_bytes", "storage.receipt_filesystem.available_bytes"}
    changed = [{"field": name, "before": lhs.get(name), "after": rhs.get(name)}
               for name in sorted(lhs.keys() | rhs.keys())
               if name not in volatile and lhs.get(name) != rhs.get(name)]
    return {"schema": SCHEMA, "kind": "comparison", "session_id": before["session_id"],
            "before_sha256": lhs_sha, "after_sha256": rhs_sha,
            "changed_fields": changed, "volatile_exclusions": sorted(volatile),
            "limitation": "Observed changes do not establish host isolation or security"}

def main():
    ap = argparse.ArgumentParser(description="Offline host state before/after receipts (no VM or sudo)")
    ap.add_argument("--phase", choices=("before", "after", "verify"), required=True)
    ap.add_argument("--session", type=pathlib.Path, help="directory printed by before")
    ap.add_argument("--out-parent", type=pathlib.Path,
                    help="default: ~/.local/state/qsol-rhel-lab/host-audits")
    ap.add_argument("--repo", type=pathlib.Path, help="optional local RHEL-LAB checkout")
    args = ap.parse_args()
    if os.geteuid() == 0:
        raise Refusal("run without sudo/root")
    if args.phase == "before" and args.session:
        raise Refusal("before creates its own new session")
    if args.phase != "before" and not args.session:
        raise Refusal("--session is required for after/verify")
    if args.phase == "before":
        parent = canonical(args.out_parent or (
            pathlib.Path.home() / ".local/state/qsol-rhel-lab/host-audits"))
        parent_fd = directory(parent, create=True, private=True)
        try:
            session_id = secrets.token_hex(12)
            os.mkdir(session_id, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        session = parent / session_id
    else:
        session = canonical(args.session)
        session_id = session.name
        if not re.fullmatch("[0-9a-f]{24}", session_id):
            raise Refusal("invalid session ID")
    fd = directory(session, private=True)
    try:
        if args.phase == "verify":
            before, first_sha = checked(fd, "before.json")
            if before.get("phase") != "before" or before.get("session_id") != session_id:
                raise Refusal("before session mismatch")
            try:
                after, second_sha = checked(fd, "after.json")
            except FileNotFoundError:
                print("VERIFIED before:", first_sha, "(after not captured)")
                return 0
            if after.get("phase") != "after" or after.get("session_id") != session_id:
                raise Refusal("after session mismatch")
            stored, _ = checked(fd, "comparison.json")
            if stored != difference(before, after, first_sha, second_sha):
                raise Refusal("comparison receipt mismatch")
            print("VERIFIED before:", first_sha, "after:", second_sha)
            return 0
        before, first_sha = None, None
        if args.phase == "after":
            try:
                os.stat("after.json", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refusal("after receipt exists; refusing overwrite")
            before, first_sha = checked(fd, "before.json")
            if before.get("phase") != "before" or before.get("session_id") != session_id:
                raise Refusal("before session mismatch")
        record = {
            "schema": SCHEMA, "phase": args.phase, "session_id": session_id,
            "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "method": "unprivileged-readonly", "network_operations": False,
            "vm_operations": False, "system": capture(session, args.repo),
            "limitation": "Source and system observations only; not a live isolation audit"}
        digest = seal(fd, args.phase + ".json", record)
        print(args.phase.upper(), "SHA256:", digest)
        if before is not None:
            report = difference(before, record, first_sha, digest)
            seal(fd, "comparison.json", report)
            print("Changed nonvolatile fields:", len(report["changed_fields"]))
        print("SESSION:", session)
        print("PRIVATE: review/redact before sharing receipts; never commit to Git.")
        return 0
    finally:
        os.close(fd)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, UnicodeError) as exc:
        print("FAIL: " + ascii(str(exc))[1:-1], file=sys.stderr)
        raise SystemExit(1)
PYTHON
