"""Command line interface.

Two kinds of thing live in different places and this is where the distinction
is enforced:

  * **configuration** — the trust anchor, capability vocabulary, roots and
    thresholds — is read from a single ``config.yaml``.
  * **installed state** — subagents and tool bindings — lives in the database,
    signed, and is put there by an explicit act: ``compile``.

A subagent is a program. Compiling one validates it fully and fails with a real
error before anything is installed, rather than a config file being re-parsed
and re-validated at every startup.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from mcp import StdioServerParameters

from .config import Config, ConfigError
from .containment.store import Store
from .crypto.keys import (
    agent_id,
    generate_keypair,
    load_private_key,
    public_bytes,
    save_private_key,
)
from .crypto.signing import b64u_encode
from .gateway.proxy import schema_hash
from .gateway.transport import MCPTransport
from .ledger.chain import Ledger, LedgerCorruption
from .supervisor.catalog import (
    CatalogError,
    compile_subagent,
    install,
    load_roles,
    sign_role,
)
from .tools.bindings import install_binding, load_bindings, sign_binding

__all__ = ["main"]

DEFAULT_KEY = Path("data/keys/operator.key")


def _load(args) -> tuple[Config, Store]:
    config = Config.load(args.config)
    return config, Store(config.database)


def _operator_key(config: Config, args):
    path = Path(args.key) if getattr(args, "key", None) else config.keys / "operator.key"
    if not path.exists():
        raise SystemExit(
            f"no operator key at {path}. Run `agent-server keygen` first — "
            f"a subagent cannot be installed without one to sign it."
        )
    return load_private_key(path)


def _server_target(config: Config, name: str):
    """Build a transport target from the configured server definition."""
    spec = config.servers.get(name)
    if spec is None:
        raise SystemExit(
            f"no server named {name!r} in config.yaml; known: {sorted(config.servers)}"
        )
    command = spec.get("command")
    if not command:
        raise SystemExit(f"server {name!r} has no command")
    args = list(command[1:])
    root = spec.get("args_root")
    if root:
        args += ["--root", str(config.policy.roots[root].path)]
    return StdioServerParameters(command=command[0], args=args)


# -- commands ---------------------------------------------------------------


def cmd_keygen(args) -> int:
    """Create an operator key. Deliberately does not need a config file: the
    config cannot be valid until an operator key exists to put in it."""
    path = Path(args.out or DEFAULT_KEY)
    if path.exists() and not args.force:
        raise SystemExit(f"{path} exists; refusing to overwrite (use --force)")
    key = generate_keypair()
    save_private_key(key, path)
    print(f"operator key written to {path} (mode 0600)\n")
    print("Add this to config.yaml:\n")
    print("operators:")
    print(f'  "{agent_id(key)}": "{b64u_encode(public_bytes(key))}"')
    return 0


def cmd_compile(args) -> int:
    config, store = _load(args)
    bindings, rejected = load_bindings(store, config.policy)
    for ident, exc in rejected:
        print(f"  warning: binding {ident} ignored — {exc}", file=sys.stderr)

    key = _operator_key(config, args)
    installed = 0
    for source in args.files:
        artifact = yaml.safe_load(Path(source).read_text()) or {}
        try:
            role = compile_subagent(artifact, policy=config.policy, bindings=bindings)
        except CatalogError as exc:
            print(f"{source}: {exc}", file=sys.stderr)
            return 1
        if args.check:
            print(f"{source}: ok — {role.name} "
                  f"({', '.join(sorted(role.capabilities))} on {role.resource})")
            continue
        install(store, sign_role(key, role))
        print(f"{source}: installed {role.name} "
              f"({', '.join(sorted(role.capabilities))} on {role.resource})")
        installed += 1
    store.close()
    return 0


def cmd_bind(args) -> int:
    """Discover a tool, pin its declared schema, and install a signed binding.

    The schema hash is taken from what the server actually advertises now. A
    server that later redefines the tool's arguments has that binding disabled
    until someone re-pins deliberately — otherwise the resolver keeps reading a
    field that no longer means what it did, and every signature still verifies
    while it does.
    """
    config, store = _load(args)
    key = _operator_key(config, args)

    resolver = config.policy.resolver_for(args.capability)
    if resolver is None:
        raise SystemExit(
            f"capability {args.capability!r} is not declared in config.yaml; "
            f"known: {sorted(config.policy.capabilities)}"
        )

    resolver_config: dict[str, Any] = {"field": args.field}
    if resolver == "path_under_root":
        root = args.root or next(iter(config.policy.roots), None)
        if root not in config.policy.roots:
            raise SystemExit(f"unknown root {root!r}; known: {sorted(config.policy.roots)}")
        resolver_config["root"] = root

    with MCPTransport(args.server, _server_target(config, args.server)) as transport:
        advertised = transport.list_tools()
        info = advertised.get(args.tool)
        if info is None:
            raise SystemExit(
                f"{args.server} does not advertise {args.tool!r}; "
                f"it offers: {sorted(advertised)}"
            )
        pinned = schema_hash(info.input_schema)

    row = sign_binding(
        key,
        server=args.server, tool=args.tool, capability=args.capability,
        resolver=resolver, resolver_config=resolver_config,
        schema_sha256=pinned,
        requires_review=not args.auto_approve,
    )
    install_binding(store, row)
    review = "" if args.auto_approve else "  [born requiring review]"
    print(f"bound {args.server}/{args.tool} -> {args.capability} "
          f"via {resolver}{review}")
    print(f"  schema pinned at {pinned[:16]}…")
    store.close()
    return 0


def cmd_roles(args) -> int:
    config, store = _load(args)
    bindings, _ = load_bindings(store, config.policy)
    roles, rejected = load_roles(store, config.policy, bindings)
    for name, role in sorted(roles.items()):
        tools = ", ".join(f"{s}/{t}" for s, t in role.tools())
        print(f"{name:<20} {role.resource:<28} {tools}")
        if role.description:
            print(f"{'':<20} {role.description}")
    for name, exc in rejected:
        print(f"{name:<20} REJECTED — {exc}", file=sys.stderr)
    if not roles:
        print("(none installed — compile a *.subagent.yaml)")
    store.close()
    return 0


def cmd_bindings(args) -> int:
    config, store = _load(args)
    bindings, rejected = load_bindings(store, config.policy)
    for (server, tool), binding in sorted(bindings.items()):
        review = "  [requires review]" if binding.requires_review else ""
        print(f"{server}/{tool:<24} {binding.capability:<18} {binding.resolver}{review}")
    for ident, exc in rejected:
        print(f"{ident} REJECTED — {exc}", file=sys.stderr)
    if not bindings:
        print("(none installed)")
    store.close()
    return 0


def cmd_agents(args) -> int:
    _config, store = _load(args)
    rows = store.query(
        "SELECT agent_id, state, denial_count, cooldown_until FROM agents "
        "ORDER BY registered_at DESC LIMIT ?", (args.limit,))
    for row in rows:
        cooling = f"  cooldown until {row['cooldown_until']}" if row["cooldown_until"] else ""
        print(f"{row['agent_id']}  {row['state']:<10} "
              f"denials={row['denial_count']}{cooling}")
    if not rows:
        print("(no agents registered)")
    store.close()
    return 0


def cmd_ledger(args) -> int:
    config, _store = _load(args)
    ledger = Ledger(config.ledger)
    try:
        count = ledger.verify()
    except LedgerCorruption as exc:
        print(f"CHAIN BROKEN at seq {exc.seq}: {exc}", file=sys.stderr)
        return 1
    print(f"chain verified — {count} entries")
    if args.tail:
        for entry in ledger.read()[-args.tail:]:
            data = json.dumps(entry["data"], sort_keys=True)
            print(f"  {entry['seq']:>5} {entry['type']:<24} {data[:100]}")
    return 0


# -- entry point ------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-server", description=__doc__)
    parser.add_argument("--config", help="path to config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create an operator signing key")
    p.add_argument("--out", help=f"key path (default {DEFAULT_KEY})")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("compile", help="validate and install *.subagent.yaml")
    p.add_argument("files", nargs="+")
    p.add_argument("--key", help="operator key (default <keys>/operator.key)")
    p.add_argument("--check", action="store_true", help="validate only, install nothing")
    p.set_defaults(func=cmd_compile)

    p = sub.add_parser("bind", help="discover a tool and install a signed binding")
    p.add_argument("server")
    p.add_argument("tool")
    p.add_argument("--capability", required=True)
    p.add_argument("--field", required=True, help="argument naming the resource")
    p.add_argument("--root", help="root name, for path resolvers")
    p.add_argument("--auto-approve", action="store_true",
                   help="install without requiring review (default: review required)")
    p.add_argument("--key", help="operator key")
    p.set_defaults(func=cmd_bind)

    p = sub.add_parser("roles", help="list installed subagents")
    p.set_defaults(func=cmd_roles)

    p = sub.add_parser("bindings", help="list installed tool bindings")
    p.set_defaults(func=cmd_bindings)

    p = sub.add_parser("agents", help="list registered agent identities")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_agents)

    p = sub.add_parser("ledger", help="verify the audit chain")
    p.add_argument("--tail", type=int, default=0, help="also print the last N entries")
    p.set_defaults(func=cmd_ledger)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
