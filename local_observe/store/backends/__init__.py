"""Store backends: one ClickHouse read path, one in-memory path, no shared transport.

``clickhouse.py`` holds the bounded HTTP client and the only SQL the platform may run;
``memory.py`` answers the same query kinds from seeded rows for tests and the offline demo. The
package is a real package (not a namespace one) so ``setuptools`` ships it: a backend that exists in
the repository and not in the wheel is a demo that works only on a checkout.
"""
