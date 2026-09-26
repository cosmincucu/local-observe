"""Validate an explicitly selected rootless Docker daemon and Compose chain.

The guard checks the account, socket access, daemon data root and optimization mode
before a caller may operate on containers. Compose selection refuses incomplete or
duplicate definitions of the synthetic monitoring services.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

from _lib.require import refuse_optimized, require
from _lib.run import run

#: Seconds allowed for the ``docker info`` read. Generous for a healthy daemon; the copies it
#: replaces used anything between 15 and 600, and a hung daemon must not hang the guard.
DAEMON_TIMEOUT = 60


def rootless_docker_guard(base: Path, uid: int, *, expected_root_dir: Path | str | None = None,
                          user_name: str | None = 'lo-stage', adopt_environment: bool = True,
                          set_runtime_dir: bool = False, timeout: float = DAEMON_TIMEOUT) -> str:
    """Refuse to continue unless only the rootless staging daemon is reachable, then adopt it.

    Args:
        base: The staging scratch root. Without ``expected_root_dir`` the daemon's data root must
            sit somewhere under it; a daemon storing its data anywhere else is not the staging one.
        uid: The staging account's uid. The process must be running as it.
        expected_root_dir: Exact required value of ``DockerRootDir``, for deployments that pin it.
        user_name: Account name that ``uid`` must resolve to, or ``None`` to check the uid only.
        adopt_environment: Point this process's ``DOCKER_HOST`` at the per-user socket. When false,
            require that ``DOCKER_HOST`` already names it - the stricter form, for a script that
            must not be the one deciding where Docker points.
        set_runtime_dir: Also export ``XDG_RUNTIME_DIR`` for that uid. Only for callers that did so
            before this existed; it changes how the CLI discovers sockets and contexts.
        timeout: Bound on the ``docker info`` read.

    Returns:
        The verified ``DockerRootDir``.

    Raises:
        ValueError: Any check failed, including running optimized, as the wrong account, with the
            rootful socket writable, on the wrong daemon, or off Linux.
    """
    refuse_optimized()
    require(sys.platform == 'linux',
            'Refusing to run outside Linux: the rootless staging daemon is a Linux user service')
    require(os.getuid() == uid, 'This script must run as the staging account (uid ' + str(uid) + ')')
    if user_name is not None:
        import pwd  # Windows has no pwd; importing at module level would make this untestable there.
        try:
            account = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:  # a uid with no passwd entry (CI containers, a deleted account) is not the staging one
            account = None
        require(account == user_name, 'Staging uid resolves to an unexpected account')
    require(not os.access('/var/run/docker.sock', os.W_OK),
            'Refusing production Docker access: the rootful socket is writable')
    socket = 'unix:///run/user/' + str(uid) + '/docker.sock'
    if adopt_environment:
        os.environ['DOCKER_HOST'] = socket
    else:
        require(os.environ.get('DOCKER_HOST') == socket, 'DOCKER_HOST must already name the rootless staging socket')
    if set_runtime_dir:
        os.environ['XDG_RUNTIME_DIR'] = '/run/user/' + str(uid)
    # A selected context overrides DOCKER_HOST; without this the checks below could describe one
    # daemon while the commands run against another.
    os.environ.pop('DOCKER_CONTEXT', None)
    root_dir = run('docker', 'info', '--format', '{{.DockerRootDir}}', timeout=timeout)
    if expected_root_dir is not None:
        require(root_dir == str(expected_root_dir), 'Unexpected Docker data root; staging daemon not the one selected')
    else:
        require(root_dir.startswith(str(base).rstrip('/') + '/'),
                'Docker data root is outside the staging scratch; refusing that daemon')
    return root_dir


#: The three Compose files a platform deployment can be built from. synthetics component moved ``gatus`` and
#: ``detector`` out of the stage fragment and into a component manifest of their own, so the chain a
#: driver must type now depends on **which** package that deployment is: a tree assembled after the
#: move carries the component and needs the third ``-f``, and a frozen tree assembled before it
#: carries the two services inside its own fragment and must not be handed a path it does not have.
PLATFORM_MANIFEST = 'components/control/platform/compose.yaml'
STAGE_FRAGMENT = 'examples/platform/staging.compose.yaml'
SYNTHETICS_MANIFEST = 'components/control/synthetics/compose.yaml'
#: The two services a synthetic loop consists of - **both** of them, in one named mapping. An engine
#: with no adapter observes nothing that files a verdict, and an adapter with no engine files
#: ``coverage`` forever; neither is a package worth starting, so a half set is a refusal.
SYNTHETIC_SERVICES = ('gatus', 'detector')
#: One key line of the canonical block shape: an all-space indent, a plain (never quoted) key, then
#: either nothing or a value separated by one space, which may be a trailing comment. A sequence
#: item, a tab, a quoted key or a flow mapping match nothing here.
YAML_KEY_LINE = re.compile(r'([ ]*)([A-Za-z0-9][A-Za-z0-9_.-]*):(?:[ \t](.*))?$')


def compose_service_names(path, label):
    """Return the service names one shipped Compose model declares, or refuse rather than guess them.

    A conservative line walk of the shape every Compose model in this repository is written in -
    ``services:`` at column zero, every service key one indent step below it - and not a YAML parser:
    these callers run on a staging host that need not have a dependency installed for them, and the
    question is only which services *this* file defines.

    The whole name set is returned rather than a two-word answer, because a name is a service only
    while it sits in the ``services`` mapping: ``volumes: gatus-data:`` declares a volume and
    ``secrets: gatus-token:`` declares a secret, and a grep for one indented keyword counted both as
    service definitions. Names outside ``services:`` are never returned, and the caller decides what
    a missing or an extra one costs.

    Every shape this cannot read is a refusal naming the file and the line, never a guess: an
    unreadable or non-UTF-8 file, a tab indent, a quoted or flow-style key, a services block that
    changes indentation half way through, or one service declared twice in the same file. A service's
    own contents are never examined at all - only lines at the indent its name sits on can be names -
    and a model that ever needs a shape outside this one is refused until this reader is widened on
    purpose.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise ValueError('The ' + label + ' at ' + str(path) + ' cannot be read: ' + type(exc).__name__
                         + '; refusing to guess which services this deployment declares') from exc
    names, section, child = [], None, None
    seen_content, seen_services, empty_services = False, False, False
    for number, line in enumerate(text.splitlines(), start=1):
        where = 'The ' + label + ' at ' + str(path)
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if line in ('---', '...'):
            require(line == '---' and not seen_content,
                    where + ' has an unsupported document boundary at line ' + str(number))
            seen_content = True
            continue
        seen_content = True
        leading = line[:len(line) - len(line.lstrip())]
        if '\t' in leading:
            raise ValueError(where + ' is indented with a tab at line ' + str(number)
                             + '; only the plain block shape is read here')
        indent = len(leading)
        if section != 'services':
            if indent > 0:
                require(not empty_services, where + ' adds entries below an empty services mapping')
                continue  # inside volumes:, secrets:, include: - contents, never a service definition
        elif child is not None and indent > child:
            continue  # one service's own keys, list items and block scalars - all deeper than a name
        match = YAML_KEY_LINE.match(line)
        if match is None:
            raise ValueError(where + ' is not in the plain block shape this reader understands (line '
                             + str(number) + '); refusing to guess which services it declares')
        key = match.group(2)
        # A comment is not a value: `services:  # the loop arrives from the component` is a block key.
        inline = (match.group(3) or '').strip()
        if inline.startswith('#'):
            inline = ''
        if indent == 0:
            require(key != 'services' or not seen_services, where + ' declares services twice')
            seen_services = seen_services or key == 'services'
            if key == 'services' and inline not in ('', '{}'):
                raise ValueError(where + ' declares its services in flow style at line ' + str(number)
                                 + '; only the plain block shape is read here')
            empty_services = key == 'services' and inline == '{}'
            section, child = ('services' if key == 'services' and not empty_services else 'other'), None
            continue
        require(inline in ('', '{}'), where + ' has an unsupported service value at line ' + str(number))
        if child is not None and indent != child:
            raise ValueError(where + ' changes indentation inside its services block at line '
                             + str(number) + '; this is not a shape this reader will guess at')
        child = indent  # the first name under services: sets the grid every other name must sit on
        require(key not in names, where + ' declares the service ' + repr(key) + ' twice; a merged chain '
                'keeps one definition, so this package is refused as inconsistent')
        names.append(key)
    return names


def platform_compose_layers(root, *, require_component):
    """Return the ``-f`` chain of one platform deployment, read off the files that deployment carries.

    One selector, called over the root each caller has already selected, by the shipped stage driver
    (``require_component=True``), by the two live support helpers and by the flat-copied telegram gate
    (``require_component=False``). Those callers cannot import each other - the gate is copied into a
    work directory of its own with only ``scripts/_lib`` beside it - which is exactly why the rule
    lives in ``_lib`` and not in three copies of itself.

    Args:
        root: The deployment tree to read: the fresh work directory a stage driver runs inside, or the
            frozen one a support helper names. Pure and read-only - nothing here creates, rewrites or
            resolves anything, and no archived stage byte is touched.
        require_component: ``True`` for a package assembled after synthetics component, which must carry
            ``components/control/synthetics/compose.yaml``; such a package is refused rather than
            started in the weaker two-file shape that boots a platform, a target and a sink and
            nothing that observes them. ``False`` for the legacy wrappers, which accept either shape
            and must keep a frozen deployment's chain exactly as long as it was started with.

    Both callers decide on the same evidence - both synthetic service names present in the one
    mapping that defines them - so neither can describe a package in a way the other would not:

    * a component whose ``services`` name **both** ``gatus`` and ``detector``, and **neither** of them
      in the fragment: three layers, in the order ``examples/platform/compose.yaml`` merges them;
    * no component, and **both** names in the fragment's ``services``: the two layers that frozen
      deployment was started with, and no path added that the package does not hold - accepted only
      when ``require_component`` is false;
    * anything else: one of the two names without the other (in either file), either name in both
      files, one service declared twice, the two names sitting outside a ``services`` mapping, or a
      missing, unreadable or unrecognisable member. Every one of those is a refusal that names the
      files, because a partial loop starts half a story and an inconsistent chain keeps whichever
      definition Compose picked - which is how a service quietly disappears.

    Returns:
        Path strings in ``-f`` order, with no private override layers in them: callers append those.

    Raises:
        ValueError: Any refusal above. Never a fallback, and never a weaker chain.
    """
    root = Path(root)
    platform, fragment = root / PLATFORM_MANIFEST, root / STAGE_FRAGMENT
    component = root / SYNTHETICS_MANIFEST
    require(platform.is_file(), 'No platform manifest at ' + str(platform) + '; this is not a platform '
            'stage tree')
    require(fragment.is_file(), 'No staging fragment at ' + str(fragment) + '; this is not a platform '
            'stage tree')
    declared = compose_service_names(fragment, 'staging fragment')
    in_fragment = sorted(set(declared) & set(SYNTHETIC_SERVICES))
    carrying = component.is_file()
    in_component = sorted(set(compose_service_names(component, 'synthetics component'))
                          & set(SYNTHETIC_SERVICES)) if carrying else []
    def absent(names):
        return [name for name in SYNTHETIC_SERVICES if name not in names]
    def incomplete(names, where):
        """One sentence naming which synthetic services ``where`` fails to declare."""
        if not names:
            return where + ' declares neither ' + ' nor '.join(SYNTHETIC_SERVICES) + ' as a service'
        return (where + ' declares ' + ' and '.join(names) + ' but not ' + ' and '.join(absent(names))
                + ' as a service')
    if carrying:
        require(not in_fragment, str(fragment) + ' still declares ' + ' and '.join(in_fragment)
                + ' and ' + str(component) + ' declares the synthetic services too; one merged chain '
                'keeps one definition, so this package is refused as inconsistent')
        require(len(in_component) == len(SYNTHETIC_SERVICES),
                incomplete(in_component, str(component)) + '; half a synthetic loop is not a known '
                'package shape, so this is refused rather than started')
        return [str(platform), str(fragment), str(component)]
    require(not require_component,
            'No synthetics component at ' + str(component) + '; this package declares no gatus/detector '
            'service, so the chain would start a platform with no synthetic loop. Include the '
            'complete synthetics component in the deployment package.')
    require(in_fragment, 'Neither ' + str(component) + ' nor ' + str(fragment) + ' declares gatus and '
            'detector in its services: this package has no synthetic loop to stage, and starting the '
            'rest of it would report lifecycle checks as if it had one')
    require(len(in_fragment) == len(SYNTHETIC_SERVICES),
            incomplete(in_fragment, str(fragment)) + ', and no synthetics component is present to supply '
            'the other; half a synthetic loop is not a known package shape')
    return [str(platform), str(fragment)]
