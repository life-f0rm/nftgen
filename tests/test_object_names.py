"""Object names (table, chain, set, map, counter, flowtable) and the names a
rule references render as bare nft tokens, so each must be an nft identifier:
a line break or a brace in one rendered more tables, chains or statements."""

import re

import pytest

from nftgen import validate
from nftgen.definitions import Definitions
from nftgen.generate import DictResolver, render_tables
from nftgen.ir import BuildError
from nftgen.rules import RuleRenderer

DEFS = Definitions.from_mappings({"interfaces": {"lo_if": ["lo"]}})

requires_nft = pytest.mark.skipif(
    not validate.can_check(), reason="nft -c not usable in this environment"
)

KINDS = ("table", "chain", "set", "map", "counter", "flowtable")
DEFAULTS = {
    "table": "t",
    "chain": "c",
    "set": "s",
    "map": "m",
    "counter": "n",
    "flowtable": "f",
}


def _tables(kind: str, name) -> list:
    """One table holding every object kind, each referenced the way a rule
    renders it: `jump`/`goto` and a vmap `jump` to the chain, `@set` lookup
    and meter, `counter name`, `snat … map @map`, `flow add @flowtable`."""
    n = {**DEFAULTS, kind: name}
    return [
        {
            "family": "inet",
            "name": n["table"],
            "sets": [{"name": n["set"], "type": "ipv4_addr", "flags": ["dynamic"]}],
            "maps": [{"name": n["map"], "type": "ifname : ipv4_addr"}],
            "counters": [n["counter"]],
            "flowtables": [{"name": n["flowtable"], "devices": "lo_if"}],
            "chains": [
                {"name": n["chain"]},
                {
                    "name": "forward",
                    "hook": "forward",
                    "policy": "accept",
                    "rules": [
                        {
                            "saddr": f"@{n['set']}",
                            "counter": n["counter"],
                            "action": {"jump": n["chain"]},
                        },
                        {
                            "meter": {
                                "set": n["set"],
                                "key": "saddr",
                                "rate": "10/second",
                            },
                            "action": {"goto": n["chain"]},
                        },
                        {"proto": "tcp", "flow-offload": n["flowtable"]},
                        {
                            "vmap": {
                                "key": "iifname",
                                "map": {"lo_if": {"jump": n["chain"]}},
                            }
                        },
                    ],
                },
                {
                    "name": "postrouting",
                    "hook": "postrouting",
                    "type": "nat",
                    "priority": "srcnat",
                    "rules": [
                        {
                            "oifname": "lo_if",
                            "action": {"snat": {"key": "oifname", "map": n["map"]}},
                        }
                    ],
                },
            ],
        }
    ]


def _render(kind: str, name) -> str:
    return render_tables(_tables(kind, name), DEFS, DictResolver({}))


# what nft's scanner reads as one name: a letter, `_` or `.` first, then
# letters, digits, `_`, `.`, `-` or `/`, 255 at most
NAMES = ["a", "A1", "_", "_a", ".a", "..", "wan-in.v4/x_1", "x" * 255]
TAKEN = [(kind, name) for kind in KINDS for name in NAMES] + [
    # keywords only where a rule references the name with `@`
    *[(kind, word) for kind in ("table", "chain", "counter") for word in ("ll", "nh")],
    *[(kind, "last") for kind in ("table", "chain", "set", "map", "counter")],
]


@pytest.mark.parametrize(("kind", "name"), TAKEN)
def test_every_name_nft_takes_renders(kind, name):
    declared = "table inet" if kind == "table" else f"    {kind}"
    assert f"\n{declared} {name} {{\n" in "\n" + _render(kind, name)


@requires_nft
@pytest.mark.parametrize(("kind", "name"), TAKEN)
def test_every_name_nft_takes_passes_nft_check(kind, name):
    result = validate.check(_render(kind, name))
    assert result.ok, result.stderr


NOT_IDENTIFIERS = [
    "1a",
    "-a",
    ".",
    "a b",
    '"a"',
    "a:b",
    "a*",
    "a\\b",
    "a;",
    "a{",
    "a\n",
    "\na",
    "wäl",
    "x" * 256,
]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("name", NOT_IDENTIFIERS)
def test_a_name_that_is_not_an_identifier_fails_naming_it(kind, name):
    with pytest.raises(
        BuildError,
        match=re.escape(f"{kind} name {name!r} is not an nft identifier"),
    ):
        _render(kind, name)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("name", [1, ["x"], {"x": 1}, ""])
def test_a_name_that_is_not_text_fails(kind, name):
    with pytest.raises(BuildError, match=re.escape(f"{kind} name must be text")):
        _render(kind, name)


@pytest.mark.parametrize(
    ("kind", "name"),
    [
        ("set", "ll"),
        ("set", "nh"),
        ("map", "ll"),
        ("map", "nh"),
        ("flowtable", "ll"),
        ("flowtable", "nh"),
        ("flowtable", "last"),
    ],
)
def test_a_keyword_after_at_fails(kind, name):
    # `@ll` and `@nh` are raw payload bases to nft, and `flow add @` takes
    # no `last`
    with pytest.raises(
        BuildError,
        match=re.escape(f"{kind} name {name!r} is a reserved nftables keyword"),
    ):
        _render(kind, name)


def test_a_multi_line_table_name_renders_no_other_table():
    # rendered an empty table `t` and a table `u` holding the chains
    with pytest.raises(BuildError, match=re.escape("table name 't { }\\ntable")):
        _render("table", "t { }\ntable inet u")


def test_a_multi_line_chain_name_renders_no_rule():
    # rendered a chain `c` holding a bare `accept` and a chain `d`
    with pytest.raises(BuildError, match=re.escape("chain name 'c {\\n accept")):
        _render("chain", "c {\n accept\n }\n chain d")


def test_a_table_name_error_names_the_source():
    tables = _tables("table", "t\n")
    with pytest.raises(BuildError, match=re.escape("host1: table name 't\\n'")):
        render_tables(tables, DEFS, DictResolver({}), source="host1")


R = RuleRenderer(DEFS, {})


@pytest.mark.parametrize("kind", ["jump", "goto"])
@pytest.mark.parametrize("target", ["c; accept", "c } chain d {", "1c", "fwd"])
def test_a_jump_target_must_be_a_chain_name(kind, target):
    # the target may be a chain declared in `raw:`, so it is not looked up,
    # and it rendered bare: `jump c; accept` is a jump and a rule accepting all
    with pytest.raises(BuildError, match=re.escape(f"`{kind}:` chain name")):
        R.render({"action": {kind: target}})


@pytest.mark.parametrize("kind", ["jump", "goto"])
def test_a_vmap_jump_target_must_be_a_chain_name(kind):
    with pytest.raises(BuildError, match=re.escape(f"`{kind}:` chain name")):
        R.render({"vmap": {"key": "iifname", "map": {"lo_if": {kind: "c; accept"}}}})
    with pytest.raises(BuildError, match=re.escape(f"`{kind}:` chain name")):
        R.render(
            {
                "vmap": {
                    "key": ["iifname", "oifname"],
                    "map": [{"match": ["lo_if", "lo_if"], kind: "c; accept"}],
                }
            }
        )


def test_a_jump_target_renders_bare():
    assert R.render({"action": {"goto": "wan-in.v4"}}) == ["goto wan-in.v4"]


def test_a_flowtable_reference_is_checked_without_its_table():
    # a renderer used on its own does not know the table's flowtables
    with pytest.raises(BuildError, match=re.escape("flowtable name 'f; accept'")):
        R.render({"proto": "tcp", "flow-offload": "f; accept"})
