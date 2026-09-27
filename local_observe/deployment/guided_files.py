"""Descriptor-relative, exclusive writes for first-install setup on POSIX."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat

from local_observe.platform.state import StateError


@contextmanager
def directory(path):
    """Open every ancestor without following a symlink, including the configured root."""
    path = Path(path)
    if os.name != 'posix' or not path.is_absolute() or '..' in path.parts:
        raise StateError('Setup requires an absolute POSIX directory without traversal')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            for part in path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        except OSError:
            raise StateError('Setup directory is missing or unsafe') from None
        yield fd
    finally:
        os.close(fd)


def protected(fd):
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise StateError('Setup directory must be owned and mode 0700')
    return {'device': info.st_dev, 'inode': info.st_ino}


@contextmanager
def private_lock(fd, name):
    """Anchor both the lock and its kernel ownership to the already-open directory."""
    import fcntl
    handle = os.open(name + '.owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=fd)
    with os.fdopen(handle, 'r+b') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise StateError('Unsafe runtime ownership lock')
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def read_file(fd, name):
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(handle, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
                raise StateError('Unsafe pre-existing setup file')
            return stream.read(65537)
    except OSError:
        raise StateError('Setup file is missing or unsafe') from None


def create_file(fd, name, data):
    """Never overwrite, truncate, follow a link or remove partial output."""
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(handle, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)
    if read_file(fd, name) != data:
        raise StateError('Setup write readback failed')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def materialize(root, plan_id, name, files, *, verify_only=False):
    """Only a matching durable marker permits recovery of a partial first install."""
    marker = (plan_id + '\n').encode('ascii')
    try:
        names = os.listdir(root)
        created = name not in names
        if created:
            if verify_only:
                raise StateError('Setup output is missing')
            os.mkdir(name, 0o700, dir_fd=root)
            os.fsync(root)
        target = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        try:
            protected(target)
            if created:
                create_file(target, '.setup-plan', marker)
            elif read_file(target, '.setup-plan') != marker:
                raise StateError('Destination belongs to another setup plan')
            present = set(os.listdir(target))
            if present - set(files) - {'.setup-plan'}:
                raise StateError('Destination contains unmanaged content')
            # Validate ALL existing content before creating any further file.
            for filename, data in files.items():
                if filename in present and read_file(target, filename) != data:
                    raise StateError('Existing setup content differs; nothing overwritten')
            for filename, data in files.items():
                if filename not in present:
                    if verify_only:
                        raise StateError('Setup output is incomplete')
                    create_file(target, filename, data)
            return {key: sha(read_file(target, key)) for key in sorted(files)}
        finally:
            os.close(target)
    except OSError:
        raise StateError('Setup write refused; retain partial output for inspection') from None
