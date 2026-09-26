"""Monitoring modules: the schema behind the word "blocks" (module contract).

deployment baseline: *"the beauty of this it's blocks, they can pick and choose what to enable"*. A **module** is the
unit of that choosing — one versioned file saying *which declared resources* this installation should
collect *what* from, *how often*, and *what it may be shown and paged about* as a result. Before this
package the word appeared in docs/COMPONENTS.md §3 (a Portainer integration, a Zeek/Suricata/Falco row
that already promises "documented per module") and in nothing else: a promise with no schema behind it.

Four modules, one contract each:

* :mod:`.schema` — the field contract, and the reason it is an explicit validator; it also holds the
  upgrade rule (how ``schema_version`` moves) and the one-sentence backup/restore answer, which are
  two of quality bar's five artefacts. The other two are: the conformance test, which is this package's
  refusal set (``tests/test_modules_*.py``), and the pinned compose, which does **not** apply — a
  module ships no container, and the collector fragment a module declares is rendered by the
  operator's own overlay into the pinned ``agent-linux`` service, not by product code.
* :mod:`.select` — ``applies_to``, resolved against declared UUIDs and indexed aliases only. The
  grammar changed on the way in; that file's docstring states what it is now and why.
* :mod:`.loader` — the directory: all-or-nothing, and honest about what it could not check
  (``unverified``/``unchecked``) instead of passing it silently.
* :mod:`.compiler` — multi-instance expansion, ported with its refusal set and **no shipped example**,
  for the reason written there.

Boundaries, because a reader looks in the wrong file otherwise
--------------------------------------------------------------
**No dashboard generation.** ``default_graphs`` is a declaration of intent consumed by the operator's
own dashboard repository. Nothing in ``local_observe/deployment/`` renders it, and
``deployment/dashboard_review.py`` — which reconciles a *private* authoring tree against a saved
SigNoz export — is not its consumer and must not become one. A graph name here is a promise about
series, not a panel.

**Nothing here is an installer.** module catalog (the catalogue) will read this package as *its* prerequisite: a
catalogue entry is a bundle of module files plus a manifest, and this is the schema that bundle is
validated against. What this package does with a directory is read it, refuse what it cannot check, and
hand back documents — it never downloads, imports, activates or writes a module, and a catalogue that
"installs" one is doing that in its own name, with its own review path, in the operator's repository.

**Collector config is the operator's.** A ``collection`` block names an OTel receiver/scrape fragment;
rendering it into a collector config is the operator's overlay, and the only gate that can prove a
fragment is renderable is ``scripts/check_foundation.py``'s ``check_collector`` against a real config
plus the conformance recipe. This product writes no collector config (deployment separation).
"""
