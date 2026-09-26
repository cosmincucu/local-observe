"""Prepare independent first-install accounts in a new private directory; never deploy."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import warnings
from urllib.parse import urlsplit

import yaml

from local_observe.platform.operator_account import make_account


class SetupError(ValueError):
    """Fixed, secret-free setup refusal."""


def checked_url(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or any(c.isspace() or ord(c) < 32 or c in '|`<>\\' for c in value)):
            raise ValueError
        _ = parsed.port
    except (ValueError, TypeError):
        raise SetupError('Component URLs must be HTTPS URLs without credentials, queries or fragments.') from None
    return value


def private_password(path, windows_acl_protected=False):
    """Read one exact UTF-8 password; no newline stripping or secret error text."""
    if os.name != 'posix' and not windows_acl_protected:
        raise SetupError('Check Windows directory ACLs, then confirm --windows-acl-protected.')
    try:
        path = Path(path)
        if path.is_symlink():
            raise ValueError
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or (os.name == 'posix' and
                    (info.st_uid != os.getuid() or info.st_mode & 0o077)):
                raise ValueError
            raw = stream.read(1025)
        if not 1 <= len(raw) <= 1024 or any(c in raw for c in (b'\n', b'\r', b'\x00')):
            raise ValueError
        return raw.decode('utf-8')
    except (OSError, ValueError):
        raise SetupError('Password file must be protected regular UTF-8 with no newline.') from None


def homepage_hash(password, binary):
    # Caddy trims stdin whitespace and bcrypt accepts at most 72 bytes.
    if password != password.strip() or len(password.encode('utf-8')) > 72:
        raise SetupError('Homepage requires at most 72 UTF-8 password bytes and no leading or trailing whitespace.')
    executable = shutil.which(str(binary)) if binary else None
    if not executable:
        raise SetupError('Homepage authentication requires --caddy-binary, or explicit --skip-homepage-auth.')
    try:
        result = subprocess.run([executable, 'hash-password', '--algorithm', 'bcrypt'],
                                input=password.encode('utf-8') + b'\n', capture_output=True, timeout=30,
                                check=False)
        encoded = result.stdout.decode('ascii').strip()
        if result.returncode or not re.fullmatch(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', encoded):
            raise ValueError
        return encoded
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SetupError('Caddy password hashing failed; no account files were written.') from None


def generate(output, username, password, urls, *, caddy_binary=None,
             skip_homepage_auth=False, windows_acl_protected=False):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise SetupError('Output already exists; first-install setup never replaces accounts.')
    if not output.parent.is_dir():
        raise SetupError('Output parent directory must already exist.')
    if os.name != 'posix' and not windows_acl_protected:
        raise SetupError('Windows relies on parent ACLs; explicitly confirm --windows-acl-protected before setup.')
    required = {'home', 'operations', 'overview', 'jobs', 'signoz'}
    if not required <= set(urls) or set(urls) - required - {'healthchecks'}:
        raise SetupError('All five component URLs are required; Healthchecks is optional.')
    urls = {key: checked_url(value) for key, value in urls.items()}
    try:
        account = make_account(username, password, identity='operator')
    except (ValueError, TypeError):
        raise SetupError('Username or password does not meet the account format.') from None
    hashed = None if skip_homepage_auth else homepage_hash(password, caddy_binary)
    files = {}
    used = {password}
    def token(name):
        value = secrets.token_urlsafe(32)
        if value in used:
            raise SetupError('Independent credential generation failed; retry setup.')
        used.add(value)
        files[name] = value.encode()
        return value
    def document(name, value):
        files[name] = (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()
    identities = {'reader': 'operator-ui', 'producer': 'detector', 'proposer': 'inventory-proposer',
                  'human': 'operator', 'executor': 'runner', 'summary': 'homepage'}
    roles = [{'identity': identity, 'role': role, 'token': token(role + '-token')}
             for role, identity in identities.items()]
    document('platform-credentials.json', roles)
    document('operator-account.json', account)
    files['homepage-overview-token'] = files['summary-token']
    for name in ('ingest-token', 'store-token', 'inventory-token', 'healthchecks-secret'):
        token(name)
    files['dagu-config.yaml'] = yaml.safe_dump({'auth': {'basic': {
        'username': username, 'password': password}}}, allow_unicode=True).encode('utf-8')
    if hashed:
        files['homepage-auth.caddy'] = ('basic_auth {\n    ' + username + ' ' + hashed + '\n}\n').encode()
    statuses = {}
    for name, url in urls.items():
        native = name in ('signoz', 'healthchecks')
        pending = native or (skip_homepage_auth and name in ('home', 'overview'))
        statuses[name] = {'url': url, 'username': username,
                          'status': 'pending-native-registration' if native else
                                    'pending-authentication' if pending else 'prepared-not-deployed',
                          'login': 'native account; email may be required' if native else
                                   'independent account, initially selected password'}
    access = {'schema': 1, 'main_page': urls['home'], 'username': username,
              'components': statuses, 'provisioned': [],
              'prepared': ['operations', 'jobs'] + ([] if skip_homepage_auth else ['homepage-auth']),
              'password_changes': 'Each component account changes independently after installation.',
              'permissions': 'POSIX directory 0700 and files 0600' if os.name == 'posix' else
                             'Windows: relies on confirmed parent ACLs; POSIX modes are not a security guarantee.'}
    document('access.json', access)
    links = [{'Services': [{name.title(): {'href': row['url'],
                                        'description': row['status'] + ': ' + row['login']}}
                          for name, row in statuses.items()]}]
    files['homepage-links.yaml'] = yaml.safe_dump(links, sort_keys=False).encode()
    mapping = {'LO_INGEST_TOKEN_FILE': 'ingest-token', 'LO_STORE_TOKEN_FILE': 'store-token',
               'LO_INVENTORY_TOKEN_FILE': 'inventory-token', 'LO_DAGU_CONFIG_FILE': 'dagu-config.yaml',
               'LO_PLATFORM_CREDENTIALS_FILE': 'platform-credentials.json',
               'LO_HOMEPAGE_TOKEN_FILE': 'homepage-overview-token',
               'LO_HEALTHCHECKS_SECRET_FILE': 'healthchecks-secret', 'LO_PRODUCER_TOKEN_FILE': 'producer-token'}
    # JSON is a path map, not a shell fragment: arbitrary parent path characters stay data.
    document('credential-paths.json', {**{key: str(output / name) for key, name in mapping.items()},
                                    'LO_DAGU_USERNAME': username,
                                    'LO_OPERATOR_ACCOUNT_FILE': '/config/operator-account.json'})
    lines = ['# Access handoff', '', 'Main page: ' + urls['home'], '', 'Selected username: ' + username,
             '', 'Independent accounts initially use your selected password. Password changes stay independent.',
             'No services were contacted or deployed; no existing account was changed.', '',
             '| Component | URL | Status |', '| --- | --- | --- |']
    lines += ['| ' + name + ' | ' + row['url'] + ' | ' + row['status'] + ' |' for name, row in statuses.items()]
    lines += ['', 'Install operator-account.json inside the platform policy directory mounted at /config.',
              'Use credential-paths.json for deployment file paths and the selected Dagu username.',
              'Import or merge homepage-links.yaml into the existing Homepage services configuration.',
              'Install homepage-auth.caddy in the Caddy site protecting Homepage and Overview.' if hashed else
              'Homepage authentication was skipped and remains pending; do not publish an unprotected portal.',
              'SigNoz and Healthchecks require native registration; the username may need an email address there.',
              'ClickHouse credentials, image pins and service config are separate; this is not a complete deployment.',
              access['permissions'], 'Keep these files private; the Dagu file contains the selected password.', '']
    files['ACCESS.md'] = '\n'.join(lines).encode('utf-8')
    try:
        output.mkdir(mode=0o700)
        for name, data in files.items():
            fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if (output / name).read_bytes() != data:
                raise OSError
        if os.name == 'posix':
            if stat.S_IMODE(output.stat().st_mode) != 0o700 or any(
                    stat.S_IMODE((output / name).stat().st_mode) != 0o600 for name in files):
                raise OSError
    except OSError:
        raise SetupError('Write/readback failed; inspect retained private partial output and use a new directory.'
                         ) from None
    return access


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--username')
    parser.add_argument('--password-file')
    for name in ('home', 'operations', 'overview', 'jobs', 'signoz'):
        parser.add_argument('--' + name + '-url', required=True)
    parser.add_argument('--healthchecks-url')
    parser.add_argument('--caddy-binary')
    parser.add_argument('--skip-homepage-auth', action='store_true')
    parser.add_argument('--windows-acl-protected', action='store_true')
    args = parser.parse_args(argv)
    try:
        username = args.username or input('Username: ')
        if args.password_file:
            password = private_password(args.password_file, args.windows_acl_protected)
        else:
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                try:
                    password = getpass.getpass('Password: ')
                    if password != getpass.getpass('Confirm password: '):
                        raise SetupError('Passwords do not match.')
                except getpass.GetPassWarning:
                    raise SetupError('A private terminal is required; unattended setup uses --password-file.') from None
        urls = {name: getattr(args, name + '_url') for name in
                ('home', 'operations', 'overview', 'jobs', 'signoz', 'healthchecks')
                if getattr(args, name + '_url')}
        generate(args.output, username, password, urls, caddy_binary=args.caddy_binary,
                 skip_homepage_auth=args.skip_homepage_auth, windows_acl_protected=args.windows_acl_protected)
    except (SetupError, EOFError, KeyboardInterrupt) as error:
        print(str(error) if isinstance(error, SetupError) else 'Setup cancelled.', file=sys.stderr)
        return 2
    print('First-install files verified. Read ACCESS.md in your output directory; native registration remains pending.')
    return 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
