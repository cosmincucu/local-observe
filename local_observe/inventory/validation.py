"""Offline schema validation plus identity and referential-integrity checks."""
import datetime as dt
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
import yaml

SCHEMAS = Path(__file__).with_name('schemas')
MAX_BYTES = 8 * 1024 * 1024
SECRET_KEYS = {'password', 'token', 'secret', 'apikey', 'privatekey', 'authorization', 'clientsecret'}
_FLATTEN = re.compile('[^a-z0-9]')
_CAMEL_BOUNDARIES = (re.compile(r'(?<=[a-z0-9])(?=[A-Z])'), re.compile(r'(?<=[A-Z])(?=[A-Z][a-z])'))
_WORD_SEPARATOR = re.compile('[^a-z0-9]+')


def is_secret_key(key: Any) -> bool:
    """Whether *key* names a credential value: the flattened name, or its last word, is a marker.

    Two rules, because one alone is wrong in each direction. The flattened whole name is matched
    against ``SECRET_KEYS`` (so ``apikey``, ``clientSecret`` and ``' api key '`` keep matching), and
    so is the **last word** of the name after camelCase is split and non-alphanumerics separate the
    rest — that is what refuses ``api_token``, ``db_password`` and ``bearer_token``, where a
    qualified head word names the kind of credential and the trailing marker says what the value
    *is*. A pointer name is admitted on purpose: ``token_file``, ``token_id`` and ``secret_ref``
    locate a credential rather than carry one, and the declared schema has ``credential_refs`` for
    exactly that. A plain substring test is refused for the same reason the last word is required:
    it would redact ``prompt_tokens``, ``max_tokens`` and ``token_hash``, which are telemetry this
    product exists to carry. Plurals are not markers and stay out of ``SECRET_KEYS`` — a plural
    rule on top of the marker ``token`` would refuse ``prompt_tokens`` for the wrong reason.
    """
    if not isinstance(key, str):
        return False
    if _FLATTEN.sub('', key.lower()) in SECRET_KEYS:
        return True
    text = key
    for pattern in _CAMEL_BOUNDARIES:
        text = pattern.sub('_', text)
    words = [word for word in _WORD_SEPARATOR.split(text.lower()) if word]
    return bool(words) and words[-1] in SECRET_KEYS


class InvalidInventory(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    def compose_node(self, parent: yaml.nodes.Node | None, index: int) -> yaml.nodes.Node | None:
        if self.check_event(yaml.AliasEvent):
            raise InvalidInventory('YAML aliases are not supported; use explicit records')
        return super().compose_node(parent, index)


def unique_mapping(loader: UniqueLoader, node: yaml.nodes.MappingNode,
                   deep: bool = False) -> dict[str, Any]:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise InvalidInventory('YAML object keys must be unique strings')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
# Timestamps must remain strings for JSON Schema, not implicit YAML datetime objects.
UniqueLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in values if tag != 'tag:yaml.org,2002:timestamp']
    for key, values in UniqueLoader.yaml_implicit_resolvers.items()
}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def read_document(path: Path | str) -> Any:
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InvalidInventory('Input exceeds 8 MiB')
    try:
        document = yaml.load(raw.decode('utf-8'), Loader=UniqueLoader)
        canonical(document)
        return document
    except (yaml.YAMLError, UnicodeError, TypeError, ValueError, RecursionError) as exc:
        raise InvalidInventory('Invalid bounded JSON-compatible YAML input') from exc


def validate_schema(document: Any, name: str) -> None:
    schemas = [json.loads(path.read_text()) for path in sorted(SCHEMAS.glob('*.json'))]
    registry = Registry().with_resources((schema['$id'], Resource.from_contents(schema)) for schema in schemas)
    schema = next(schema for schema in schemas if schema['$id'].endswith('/' + name + '.json'))
    validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
    error = next(validator.iter_errors(document), None)
    if error:
        path = '/'.join(map(str, error.absolute_path)) or '<root>'
        # Validation messages can include values; do not echo suspected credentials.
        raise InvalidInventory(f'{name}: invalid {error.validator} at {path}')


def alias_key(alias: dict[str, Any]) -> tuple[str, str, str]:
    value = alias['value']
    if value != value.strip() or not value:
        raise InvalidInventory('Alias contains surrounding whitespace')
    if alias['type'] == 'hostname':
        value = value.rstrip('.').lower()
        if not value or any(char.isspace() for char in value):
            raise InvalidInventory('Invalid hostname alias')
    elif alias['type'] == 'ip':
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise InvalidInventory('Invalid IP alias') from exc
    return alias.get('scope', ''), alias['type'], value


def check_attributes(attributes: dict[str, Any]) -> None:
    for key, value in attributes.items():
        if is_secret_key(key):
            raise InvalidInventory('Credential values are forbidden; use credential_refs')
        if isinstance(value, float) and not math.isfinite(value):
            raise InvalidInventory('Non-finite attribute value')


def declared(document: dict[str, Any]) -> dict[str, Any]:
    validate_schema(document, 'declared')
    ids, aliases = set(), set()
    for resource in document['resources']:
        if resource['id'] in ids:
            raise InvalidInventory('Duplicate resource UUID')
        ids.add(resource['id'])
        check_attributes(resource['attributes'])
        for alias in resource['aliases']:
            key = alias_key(alias)
            if key in aliases:
                raise InvalidInventory('Duplicate or colliding normalized alias')
            aliases.add(key)
    for resource in document['resources']:
        for relation in resource['relations']:
            if relation['target'] not in ids:
                raise InvalidInventory('Relation target is not declared')
        if resource['kind'] == 'credential-reference' and not resource.get('credential_refs'):
            raise InvalidInventory('Credential-reference resources require credential_refs')
    return document


def timestamp(value: str) -> dt.datetime:
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError('naive time')
        return result.astimezone(dt.timezone.utc)
    except (AttributeError, ValueError) as exc:
        raise InvalidInventory('Expected timezone-aware ISO timestamp') from exc


def utc_text(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec='microseconds')


def observed(document: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    validate_schema(document, 'observed')
    if timestamp(document['observed_at']) > now + dt.timedelta(seconds=60):
        raise InvalidInventory('Observation timestamp exceeds clock-skew allowance')
    ids = set()
    for observation in document['observations']:
        if observation['observation_id'] in ids:
            raise InvalidInventory('Duplicate source observation identity')
        ids.add(observation['observation_id'])
        check_attributes(observation['attributes'])
        keys = [alias_key(alias) for alias in observation['aliases']]
        if len(set(keys)) != len(keys):
            raise InvalidInventory('Duplicate normalized observed alias')
    return document
