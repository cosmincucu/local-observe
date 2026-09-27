"""Explicit startup wiring for optional guided setup and trusted runner services."""
from pathlib import Path


def configured_services(store, policy, environ):
    from local_observe.platform.runner_handoff import RunnerHandoff, strict_request
    from .guided import GuidedSetup

    runners = setup = None
    if 'LO_TRUSTED_RUNNERS_FILE' in environ:
        path = environ['LO_TRUSTED_RUNNERS_FILE']
        if not path:
            raise ValueError('LO_TRUSTED_RUNNERS_FILE is blank')
        with Path(path).open('rb') as stream:
            config = strict_request(stream.read(65537))
        if (not isinstance(config, dict) or set(config) != {'schema_version', 'runners'}
                or type(config['schema_version']) is not int or config['schema_version'] != 1):
            raise ValueError('Invalid trusted runner configuration')
        runners = RunnerHandoff(store, policy, config['runners'])
    selected = ('LO_GUIDED_SETUP_ROOT' in environ, 'LO_GUIDED_SETUP_RUNNER' in environ)
    if any(selected):
        if not all(selected) or not all(environ[key] for key in ('LO_GUIDED_SETUP_ROOT', 'LO_GUIDED_SETUP_RUNNER')):
            raise ValueError('Guided setup requires both its protected root and runner identity')
        root = Path(environ['LO_GUIDED_SETUP_ROOT'])
        if not root.is_absolute() or '..' in root.parts:
            raise ValueError('Guided setup requires an absolute protected root')
        setup = GuidedSetup(store, root, environ['LO_GUIDED_SETUP_RUNNER'])
    return runners, setup
