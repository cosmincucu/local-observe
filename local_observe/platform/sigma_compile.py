"""Build-time Sigma adapter. Requires the separate pinned Python 3.13 compiler."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

import yaml
from sigma.backends.clickhouse.clickhouse import ClickhouseBackend
from sigma.collection import SigmaCollection
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from typing import Any

#: The tuning blocks an author must write beside a rule, and the closed vocabularies inside them.
#: They live here rather than in a document because a rule that does not carry them must not build:
#: `measured:` is what separates "this rule was counted" from "this rule was written", and
#: `parameters:` is how a rule names an operator input the build is not allowed to invent. The exact
#: keys and the exact safe direction of every parameter are asserted on the build path below, so the
#: anonymisation rule and the fail-closed rule are build rules and not review comments.
MEASUREMENT_KEYS = ('false_positives', 'because', 'window', 'population', 'measured_on', 'source')
#: The five fields a `measured:` block needs filled in before its count means anything. A missing or
#: null one is `unmeasured`, never "zero false positives": the honest direction of an absent number
#: is a smaller count of trusted rules, because that is what an operator can check.
MEASURED_KEYS = ('false_positives', 'window', 'population', 'measured_on', 'source')
UNSHIPPED_KEYS = ('blocker', 'reason', 'refusal')
UNSHIPPED_BLOCKERS = ('compile', 'construct', 'policy', 'noise')
#: Which blockers are claims about the compiler rather than about noise, and so must quote the refusal
#: text the pinned gate actually raises. `tests/compiler/` re-measures it; a stale quote fails there.
REFUSAL_BLOCKERS = ('compile', 'construct')
PARAMETER_KEYS = ('source', 'lanes', 'empty', 'why_empty_is_safe')
#: The only two answers to "what happens when the operator supplies nothing". `deny-all` means no
#: identity and no exception is known, so the rule is at its loudest; `refuse-to-build` means no
#: artifact exists, so no deployment can point at a rule that silently answers "all clear". A
#: permissive spelling is deliberately absent: the failure mode this set exists to make impossible is
#: a missing allowlist read as "nothing to deny, so everything is permitted", which turns an absent
#: overlay into silence. Neither direction is enforceable from a build product today — no placeholder
#: in the SQL names a declared input, and no runtime reads the metadata — so the shipping gate refuses
#: the block whichever way it is spelled and these two values state what a future binding must do (#234).
PARAMETER_EMPTY = ('deny-all', 'refuse-to-build')

FIELDS = {'Body': 'body',
          'Image': "if(mapContains(attributes_string, 'process.executable'), "
                   "attributes_string['process.executable'], NULL)",
          'CommandLine': "if(mapContains(attributes_string, 'process.command_line'), "
                         "attributes_string['process.command_line'], NULL)"}


class PredicateBackend(ClickhouseBackend):
    def finalize_query_default(self, rule: SigmaRule | SigmaCorrelationRule, query: str,
                               index: int, state: ConversionState) -> Any:
        return query


def _text(value: Any) -> bool:
    """True when `value` is a non-empty printable string, which is what every prose bound here means."""
    return isinstance(value, str) and bool(value.strip())


def measurement(document: dict[str, Any]) -> dict[str, Any]:
    """Return the rule's `measured:` block in the one shape the runner may report from.

    Fails closed on an absent or incomplete block: the answer is `unmeasured` with the author's own
    `because:` text as the reason, never a guessed zero. Only a complete block — a non-negative
    integer count, and a named window, population, date and place the count came from — is reported
    as `measured`, because a count without the window it was counted over is not a measurement.
    """
    block = document.get('measured')
    if block is None:
        raise ValueError('A rule must carry a measured: block; write `false_positives: null` and a'
                         ' `because:` sentence when nothing has been counted')
    if not isinstance(block, dict):
        raise ValueError('measured: must be a block of named fields')
    unknown = sorted(set(block) - set(MEASUREMENT_KEYS))
    if unknown:
        raise ValueError('Unknown measured: field ' + ','.join(unknown) + '; the admitted set is '
                         + ','.join(MEASUREMENT_KEYS))
    counted = block.get('false_positives')
    if counted is not None and (isinstance(counted, bool) or not isinstance(counted, int) or counted < 0):
        raise ValueError('measured.false_positives must be a non-negative integer, or null when nothing'
                         ' has been counted; a value that is neither is a typo, not a measurement')
    complete = (isinstance(counted, int) and not isinstance(counted, bool) and counted >= 0
                and all(_text(block.get(key)) for key in MEASURED_KEYS if key != 'false_positives'))
    if complete:
        return {'status': 'measured', 'false_positives': counted,
                'window': block['window'], 'population': block['population'],
                'measured_on': block['measured_on'], 'source': block['source']}
    if not _text(block.get('because')):
        raise ValueError('An unmeasured rule must state measured.because: in one sentence; an'
                         ' unexplained absence is a missing block with better formatting')
    return {'status': 'unmeasured', 'reason': ' '.join(str(block['because']).split())}


def parameters(document: dict[str, Any]) -> dict[str, Any]:
    """Validate the operator inputs a rule names, and return them with their fail-closed policy.

    A parameter is a *name, a source and a policy* — never a value. The build refuses an inline list
    (there is no admitted key that can hold one), so an identity list cannot reach a compiled artifact
    or a shipped example by accident, which is the shape the source estate's allowlist file had. The
    empty case is mandatory and must be one of `PARAMETER_EMPTY`: the safe direction of an absent
    overlay is the rule getting louder or the build refusing to emit, never the rule reporting clear.

    Everything returned here is a *declaration*, and nothing here performs it: no resolver binds the
    named source and no query placeholder exists for it, so `build_gate` refuses to ship a non-empty
    block until one can (#234). This function stays the shape-and-policy check the pure build uses.
    """
    block = document.get('parameters') or {}
    if not isinstance(block, dict):
        raise ValueError('parameters: must be a block of named operator inputs')
    out: dict[str, Any] = {}
    for name in sorted(block):
        item = block[name]
        if not isinstance(item, dict):
            raise ValueError('parameter ' + str(name) + ' must be a block')
        unknown = sorted(set(item) - set(PARAMETER_KEYS))
        if unknown:
            raise ValueError('parameter ' + str(name) + ' carries ' + ','.join(unknown) + '; no'
                             ' parameter may hold a value, the admitted keys are '
                             + ','.join(PARAMETER_KEYS))
        if not _text(item.get('source')):
            raise ValueError('parameter ' + str(name) + ' must name where its value comes from')
        if item.get('empty') not in PARAMETER_EMPTY:
            raise ValueError('parameter ' + str(name) + ' must state empty: as one of '
                             + ','.join(PARAMETER_EMPTY) + '; an absent operator input may make a'
                             ' rule louder or refuse to build, never answer "all clear"')
        if not _text(item.get('why_empty_is_safe')):
            raise ValueError('parameter ' + str(name) + ' must state why_empty_is_safe: in one'
                             ' sentence, because the safe direction has to be readable by whoever'
                             ' is paged')
        lanes = item.get('lanes', [])
        if not isinstance(lanes, dict) or any(not _text(key) or not _text(value) for key, value in lanes.items()):
            raise ValueError('parameter ' + str(name) + ' lanes must be a block of named lanes')
        out[str(name)] = {'source': ' '.join(str(item['source']).split()), 'empty': item['empty'],
                          'why_empty_is_safe': ' '.join(str(item['why_empty_is_safe']).split()),
                          'lanes': {key: lanes[key] for key in sorted(lanes)} if lanes else {}}
    return out


def authoring(document: dict[str, Any]) -> dict[str, Any]:
    """Check the blocks this repo's rule-authoring contract requires, and return what survives building.

    `enabled:` is mandatory and exact, because "shipped" and "drafted" are the two states a deployment
    distinguishes and a missing flag must not silently read as either. `why:` is mandatory prose: the
    source discipline being ported is a rule that explains what it cannot see, and a rule nobody can
    explain is a rule nobody can debug at 3am. `unshipped:` is required exactly when the rule is off,
    and for a compile blocker it must quote the refusal the gate really gives.
    """
    if document.get('enabled') is not True and document.get('enabled') is not False:
        raise ValueError('A rule must state enabled: true or enabled: false; nothing is shipped on an'
                         ' assumed flag')
    if not _text(document.get('why')):
        raise ValueError('A rule must carry a why: block saying what it asserts and what it cannot see')
    tuned = {'measurement': measurement(document), 'parameters': parameters(document)}
    block = document.get('unshipped')
    if document['enabled'] is False and not isinstance(block, dict):
        raise ValueError('A rule with enabled: false must carry an unshipped: block with a blocker'
                         ' and a reason; a silently dropped rule is not a decision')
    if document['enabled'] is True and block is not None:
        raise ValueError('A rule with enabled: true cannot also carry unshipped:; pick one')
    if block is None:
        return tuned
    unknown = sorted(set(block) - set(UNSHIPPED_KEYS))
    if unknown:
        raise ValueError('Unknown unshipped: field ' + ','.join(unknown) + '; the admitted set is '
                         + ','.join(UNSHIPPED_KEYS))
    if block.get('blocker') not in UNSHIPPED_BLOCKERS:
        raise ValueError('unshipped.blocker must be one of ' + ','.join(UNSHIPPED_BLOCKERS))
    if not _text(block.get('reason')):
        raise ValueError('unshipped.reason must say in prose why no artifact is built')
    if block['blocker'] in REFUSAL_BLOCKERS and not _text(block.get('refusal')):
        raise ValueError('unshipped.blocker ' + block['blocker'] + ' must quote the exact refusal the'
                         ' pinned compiler gate gives, so the reason cannot go stale')
    if block['blocker'] not in REFUSAL_BLOCKERS and 'refusal' in block:
        raise ValueError('unshipped.refusal is only for a blocker the compiler produces')
    return tuned


def compile_rule(raw: str) -> dict[str, Any]:
    if len(raw.encode()) > 65536:
        raise ValueError('Rule exceeds build limit')
    document = yaml.safe_load(raw)
    tuned = authoring(document)
    if document.get('logsource') != {'product': 'linux', 'category': 'process_creation'}:
        raise ValueError('Only the linux process_creation mapping is enabled')
    detection = document['detection']
    if not isinstance(detection.get('condition'), str):
        raise ValueError('Exactly one Sigma condition is required')
    used = set()
    def selection(value):
        if isinstance(value, list):
            for item in value:
                selection(item)
            return
        if not isinstance(value, dict) or not value:
            raise ValueError('Field-based selections are required')
        for key, values in value.items():
            field, *modifiers = key.split('|')
            if field not in FIELDS or not modifiers or set(modifiers) - {'contains', 'startswith', 'endswith', 'all'}:
                raise ValueError('Unsupported field or modifier; extend fixtures before enabling')
            if sum(mod in ('contains', 'startswith', 'endswith') for mod in modifiers) != 1:
                raise ValueError('One tested string-match modifier is required')
            values = values if isinstance(values, list) else [values]
            if not values or any(not isinstance(v, str) or not v or not v.isascii() for v in values):
                raise ValueError('Initial mapping supports nonempty ASCII string values only')
            used.add(field)
    for key, value in detection.items():
        if key != 'condition':
            selection(value)
    collection = SigmaCollection.from_yaml(raw)
    if len(collection.rules) != 1:
        raise ValueError('One rule per artifact')
    predicates = PredicateBackend().convert(collection)
    if len(predicates) != 1:
        raise ValueError('One bounded query per artifact')
    projection = ', '.join(FIELDS[field] + ' AS ' + field for field in sorted(used))
    valid = ' AND '.join('isNotNull(' + field + ')' for field in sorted(used))
    sql = ('WITH logs AS (SELECT ' + projection + ' FROM signoz_logs.distributed_logs_v2\n'
           'WHERE timestamp >= {start_ns:UInt64} AND timestamp < {end_ns:UInt64}\n'
           "AND resources_string['resource_id'] = {resource_id:String}\n"
           "AND attributes_string['event.dataset'] = {dataset:String})\n"
           'SELECT count() AS source_count, countIf(' + valid + ') AS usable_count,\n'
           'countIf(coalesce((' + predicates[0] + '), false)) AS match_count FROM logs FORMAT JSON')
    return {'schema_version': 1, 'rule_id': str(collection.rules[0].id),
            'rule_sha256': hashlib.sha256(raw.encode()).hexdigest(),
            'compiler': {name: importlib.metadata.version(name) for name in ('pysigma', 'pysigma-backend-clickhouse')},
            'mapping': 'signoz-logs-v2-linux-process-v1', 'dataset': 'linux.process_creation',
            'required_fields': sorted(used),
            # Both blocks survive compilation because the runner and the deployment may only read the
            # reviewed artifact (CONTRACT.md), and "1 of 2 shipped rules is unmeasured" plus "this SQL
            # presumes an operator input" are facts about the deployed thing. They are checksummed
            # with the rule: editing `why:` or `measured:` moves `rule_sha256`, which is the runner's
            # `rule_version`, which an existing evaluation cursor refuses.
            'measurement': tuned['measurement'], 'parameters': tuned['parameters'],
            'sql': sql,
            'sql_sha256': hashlib.sha256(sql.encode()).hexdigest()}


def build_gate(raw: str) -> dict[str, Any]:
    """Build enabled rules without unresolved operator inputs for shipping.

    ``compile_rule`` validates parameter declarations as authoring metadata. Neither the compiler
    nor the runner binds those inputs, so this shipping gate must refuse every nonempty declaration.
    Disabled rules retain their own stated reason for refusing the build.
    """
    document = yaml.safe_load(raw)
    if document.get('enabled') is True:
        # Keep declaration validation errors specific before refusing otherwise valid inputs.
        declared = parameters(document)
        if declared:
            naming = ', '.join(f'{name} (empty: {declared[name]["empty"]})' for name in sorted(declared))
            raise ValueError('Operator inputs are unresolved: ' + naming + '; no artifact is built '
                             'until input binding exists')
        return compile_rule(raw)
    unshipped = document.get('unshipped')
    quoted = unshipped.get('reason') if isinstance(unshipped, dict) else None
    detail = ' '.join(str(quoted).split()) if _text(quoted) else 'the rule states no unshipped.reason'
    raise ValueError('Rule is not enabled, so no artifact is built; ' + detail)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rule', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 13):
        parser.error('Use the pinned Python 3.13 compiler environment')
    artifact = build_gate(args.rule.read_text(encoding='utf-8'))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + '\n', encoding='utf-8')
