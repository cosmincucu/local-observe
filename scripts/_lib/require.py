"""Explicit runtime guards that remain active under Python optimization.

Guarded operational entrypoints also refuse optimized execution before host access.
"""
from __future__ import annotations

import sys
from typing import Any


def optimized() -> bool:
    """Return whether this interpreter runs with ``-O``/``-OO``, which strips every ``assert``."""
    return bool(sys.flags.optimize)


def require(condition: Any, message: str) -> None:
    """Raise ``ValueError(message)`` unless ``condition`` holds; never strippable by ``-O``.

    Args:
        condition: The thing that must be true to continue.
        message: What is wrong, and safe to print: it reaches report JSONs and terminal output.

    Raises:
        ValueError: ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def refuse_optimized() -> None:
    """Stop a script whose guards would have been stripped by ``-O`` before it reached them.

    Raises:
        ValueError: The interpreter runs optimized. Call as the first statement of ``main()``,
            before any action, so nothing mutates state on the way to the refusal.
    """
    require(not optimized(),
            'Refusing optimized Python: -O strips assert, and the guards in this script protect a live host')
