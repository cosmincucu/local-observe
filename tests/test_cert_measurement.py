"""Real loopback TLS when OpenSSL is available; no external network or supplied keys."""
import datetime as dt
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from local_observe.platform.cert_measurement import TLSProvider, MeasurementError, validate_target
from local_observe.platform.certcheck import run_cert_check

OPENSSL = shutil.which('openssl')


class MeasurementTests(unittest.TestCase):
    def test_configuration_refuses_dns_destination_and_unbounded_timeout(self):
        for address, timeout in [('service.example.com', 10), ('127.0.0.1', True), ('127.0.0.1', 21)]:
            with self.assertRaises(MeasurementError):
                validate_target('service.example.com', address, 443, timeout)

    def test_transport_error_is_fixed_and_never_resolves(self):
        provider = TLSProvider('127.0.0.1')
        with mock.patch('socket.socket', side_effect=OSError('private-server-details')):
            with self.assertRaisesRegex(MeasurementError, '^Certificate measurement unavailable$'):
                provider('service.example.com', 443)
            result = run_cert_check('cert', '00000000-0000-4000-8000-000000000001',
                                    'service.example.com', provider, clock=lambda: dt.datetime.now(dt.timezone.utc))
        self.assertEqual(result.samples, [])
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0]['status'], 'firing')
        self.assertEqual(result.error, 'fetch-error')

    @unittest.skipUnless(OPENSSL, 'OpenSSL executable is needed for generated local TLS fixture')
    def test_real_verified_certificate_san_mismatch_and_untrusted_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '40',
                            '-subj', '/CN=fixture.example', '-addext', 'subjectAltName=DNS:fixture.example,IP:127.0.0.1',
                            '-keyout', str(key), '-out', str(cert)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(3)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                failures = []

                def serve():
                    try:
                        for _ in range(3):
                            client, _ = listener.accept()
                            with client:
                                client.settimeout(5)
                                try:
                                    with context.wrap_socket(client, server_side=True) as peer:
                                        peer.recv(1)
                                except (ssl.SSLError, ConnectionError):
                                    pass  # Clients close after measurement or refuse the untrusted CA.
                    except Exception as exc:
                        failures.append(type(exc).__name__)

                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    provider = TLSProvider('127.0.0.1', ca_file=str(cert), timeout=3)
                    facts = provider('fixture.example', port)
                    self.assertTrue(facts.chain_valid)
                    self.assertIn('fixture.example', facts.sans)
                    result = run_cert_check('cert', '00000000-0000-4000-8000-000000000001',
                                            'wrong.example', provider, port=port,
                                            clock=lambda: dt.datetime.now(dt.timezone.utc))
                    mismatch = next(e for e in result.events if e['condition'].endswith('hostname-matches-san'))
                    self.assertEqual(mismatch['status'], 'firing')
                    with self.assertRaises(MeasurementError):
                        TLSProvider('127.0.0.1', timeout=3)('fixture.example', port)
                finally:
                    thread.join(timeout=16)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])

    @unittest.skipUnless(OPENSSL, 'OpenSSL executable is needed for generated local TLS fixture')
    def test_real_dns_san_spelling_an_ip_does_not_authenticate_ip_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '40',
                            '-subj', '/CN=fixture.example', '-addext', 'subjectAltName=DNS:127.0.0.1',
                            '-keyout', str(key), '-out', str(cert)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                failures = []

                def serve():
                    try:
                        for _ in range(1):
                            client, _ = listener.accept()
                            with client:
                                client.settimeout(5)
                                try:
                                    with context.wrap_socket(client, server_side=True) as peer:
                                        peer.recv(1)
                                except (ssl.SSLError, ConnectionError):
                                    pass  # Clients close after measurement or refuse the untrusted CA.
                    except Exception as exc:
                        failures.append(type(exc).__name__)

                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    provider = TLSProvider('127.0.0.1', ca_file=str(cert), timeout=3)
                    result = run_cert_check('cert', '00000000-0000-4000-8000-000000000001',
                                            '127.0.0.1', provider, port=port,
                                            clock=lambda: dt.datetime.now(dt.timezone.utc))
                    mismatch = next(e for e in result.events if e['condition'].endswith('hostname-matches-san'))
                    self.assertEqual(mismatch['status'], 'firing')
                    self.assertEqual(result.samples[2]['value'], False)
                finally:
                    thread.join(timeout=16)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])
