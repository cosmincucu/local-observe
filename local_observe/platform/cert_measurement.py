"""Verified TLS facts for one explicit IP destination; Gatus remains the probe engine.

No DNS, HTTP, unverified fallback or raw certificate storage. A rejected chain
(including expiry) is unavailable measurement, never fabricated certificate facts.
"""
import datetime as dt
import ipaddress
import socket
import ssl
import time

from .certcheck import CertFacts, _dns_name


class MeasurementError(ValueError):
    """A fixed, non-sensitive measurement refusal."""


def validate_target(host, connect_ip, port, timeout):
    try:
        if not isinstance(host, str) or not isinstance(connect_ip, str):
            raise ValueError
        ipaddress.ip_address(connect_ip)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _dns_name(host):
                raise ValueError from None
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError
        if type(timeout) is not int or not 1 <= timeout <= 20:
            raise ValueError
    except (ValueError, TypeError):
        raise MeasurementError('Invalid certificate target') from None


class TLSProvider:
    def __init__(self, connect_ip, *, timeout=10, ca_file=None):
        validate_target(connect_ip, connect_ip, 443, timeout)
        self.address, self.timeout = connect_ip, timeout
        self.context = ssl.create_default_context(cafile=ca_file)
        # Verify the chain first; certcheck independently records the SAN verdict.
        self.context.check_hostname = False

    def __call__(self, host, port):
        validate_target(host, self.address, port, self.timeout)
        family = socket.AF_INET6 if ipaddress.ip_address(self.address).version == 6 else socket.AF_INET
        deadline = time.monotonic() + self.timeout
        try:
            with socket.socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(self.timeout)
                raw.connect((self.address, port))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                raw.settimeout(remaining)
                with self.context.wrap_socket(raw, server_hostname=host) as peer:
                    cert = peer.getpeercert()
            sans = cert.get('subjectAltName', ())
            if not isinstance(sans, (tuple, list)) or len(sans) > 100:
                raise ValueError
            names = []
            try:
                ipaddress.ip_address(host)
                expected_kind = 'IP Address'
            except ValueError:
                expected_kind = 'DNS'
            for kind, value in sans:
                if kind == expected_kind:
                    if not isinstance(value, str) or len(value) > 253:
                        raise ValueError
                    names.append(value)
            expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), dt.timezone.utc)
            return CertFacts(expires.isoformat().replace('+00:00', 'Z'), True, names)
        except (OSError, ValueError, KeyError, TypeError, OverflowError):
            raise MeasurementError('Certificate measurement unavailable') from None
