"""Isolated conformance receiver, not a phone/push channel. No approval endpoints.

Runs as ``python /checks/notification_sink.py`` in the platform image (see
``examples/platform/staging.compose.yaml``), so its bearer token arrives as a mounted file exactly
like every other credential on that host: ``LO_NOTIFY_TOKEN_FILE`` names it, the value never does.
"""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import secrets
import sqlite3
import sys

# The image lays the product at /app (components/control/platform/Dockerfile: `COPY local_observe
# /app/local_observe`) and this file is run from /checks, which is what sys.path[0] holds, so /app
# has to be named for the import below. Appended rather than inserted: the test suite imports this
# module out of a working tree, and a /app that happens to exist on that machine must not shadow the
# tree the tests are about.
sys.path.append('/app')

from local_observe.credentials import read_credential

DATABASE = '/data/receipts.db'


class Handler(BaseHTTPRequestHandler):
    #: The bearer token this receiver accepts, loaded once by :func:`main`. Empty until then, and an
    #: empty value refuses everything: a sink that never read its credential serves no receipts.
    token = ''

    def log_message(self, *args):
        pass

    def reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorised(self) -> bool:
        """True when the request carries exactly one Authorization header holding the loaded token.

        Compared against :attr:`Handler.token`, read once at startup, never against a per-request
        environment lookup: the credential is one constant for the life of the process.
        """
        if not self.token:
            return False
        headers = self.headers.get_all('Authorization') or []
        return len(headers) == 1 and secrets.compare_digest(headers[0], 'Bearer ' + self.token)

    def do_GET(self):
        if not self.authorised():
            return self.reply(401, {})
        with closing(sqlite3.connect(DATABASE)) as connection:
            rows = [json.loads(row[0]) for row in connection.execute('SELECT payload FROM receipts ORDER BY rowid LIMIT 100')]
        return self.reply(200, {'receipts': rows})

    def do_POST(self):
        if not self.authorised():
            return self.reply(401, {})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 1 <= length <= 100000:
                return self.reply(413, {})
            raw = self.rfile.read(length)
            body = json.loads(raw)
            delivery_id = body['delivery_id']
            if self.headers.get('Idempotency-Key') != delivery_id:
                return self.reply(400, {})
            fingerprint = hashlib.sha256(raw).hexdigest()
            with closing(sqlite3.connect(DATABASE)) as connection, connection:
                connection.execute('PRAGMA synchronous=FULL')
                old = connection.execute('SELECT fingerprint FROM receipts WHERE id=?', (delivery_id,)).fetchone()
                if old and old[0] != fingerprint:
                    return self.reply(409, {})
                connection.execute('INSERT OR IGNORE INTO receipts VALUES (?,?,?)', (delivery_id, fingerprint, raw.decode()))
            return self.reply(202, {'accepted': True, 'delivery_id': delivery_id})
        except (ValueError, KeyError):
            return self.reply(400, {})


def main() -> None:
    """Load the bearer token once, prepare the receipt database, then serve.

    The credential is read here, before the database is touched, not per request: with
    ``LO_NOTIFY_TOKEN_FILE`` pointing at a file that is absent or unreadable, this container must die
    on boot -- loudly, in its own logs -- rather than come up and answer every request with a 401
    that reads like a wrong token from a caller rather than a missing one from the deployment.
    """
    Handler.token = read_credential('LO_NOTIFY_TOKEN')
    with closing(sqlite3.connect(DATABASE)) as connection, connection:
        connection.execute('CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,payload TEXT NOT NULL)')
    HTTPServer(('0.0.0.0', 8010), Handler).serve_forever()


if __name__ == '__main__':
    main()
