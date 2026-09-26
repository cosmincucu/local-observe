"""Shared command, guard, credential and report helpers for repository tooling.

When packaging a standalone script, include this directory beside it as ``_lib``.
Flat scripts add their parent directory to sys.path before importing these helpers.
Product modules under ``local_observe`` do not depend on this tooling package.

Import functions from their modules; this package deliberately binds no names.
"""

