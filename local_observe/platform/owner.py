"""OS-held single-service lock; released by the kernel after abrupt process death."""
from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path


@contextmanager
def exclusive_owner(database: Path | str) -> Iterator[None]:
    path = Path(str(database) + '.owner.lock')
    if path.is_symlink():
        raise ValueError('Refusing symlink ownership lock')
    with path.open('a+b') as stream:
        if os.name == 'nt':
            import msvcrt
            if stream.tell() == 0:
                stream.write(b'\0')
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
