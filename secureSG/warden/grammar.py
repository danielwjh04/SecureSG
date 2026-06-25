"""Build a tool-grounded GBNF grammar that constrains policy generation.

The grammar restricts generation to a JSON object whose tool-name fields may only
reference tools in the supplied inventory, and whose verdict/tier values are the
known enums. It is a plain string (no native dependency, so it is unit-testable),
compiled to a llama_cpp grammar only at inference time. Grounding the grammar in
the inventory makes hallucinated tool names structurally impossible — the model
literally cannot emit a tool that does not exist.
"""

from secureSG.guard.taint import TaintTier
from secureSG.schemas.verdict import Verdict

_VERDICTS: tuple[str, ...] = tuple(v.value for v in Verdict)
_TIERS: tuple[str, ...] = tuple(t.name for t in TaintTier)


def _json_string_rule(value: str) -> str:
    """GBNF literal that matches the JSON string ``"value"`` (quotes included)."""
    inner = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"\\"' + inner + '\\""'


def build_policy_grammar(tools: list[str]) -> str:
    """Build a GBNF grammar grounding a generated policy in ``tools``.

    The grammar accepts a JSON object with the five tool-treatment fields; arrays
    and map keys may only be tools from the inventory, and map values only the
    verdict/tier enums.

    Raises:
        ValueError: if the tool inventory is empty (nothing to govern).

    Time complexity: O(tool count). Space complexity: O(grammar size).
    """
    if not tools:
        raise ValueError("cannot build a policy grammar from an empty tool inventory")
    name_rule = " | ".join(_json_string_rule(tool) for tool in sorted(set(tools)))
    verdict_rule = " | ".join(_json_string_rule(verdict) for verdict in _VERDICTS)
    tier_rule = " | ".join(_json_string_rule(tier) for tier in _TIERS)
    root = (
        '"{" ws '
        + _json_string_rule("denylist") + ' ws ":" ws tools ws "," ws '
        + _json_string_rule("external_comms_tools") + ' ws ":" ws tools ws "," ws '
        + _json_string_rule("content_scan_sources") + ' ws ":" ws tools ws "," ws '
        + _json_string_rule("tool_rules") + ' ws ":" ws verdicts ws "," ws '
        + _json_string_rule("taint_sources") + ' ws ":" ws tiers ws "}"'
    )
    return "\n".join(
        (
            f"root ::= {root}",
            'tools ::= "[" ws ( name ( ws "," ws name )* ws )? "]"',
            'verdicts ::= "{" ws ( pair ( ws "," ws pair )* ws )? "}"',
            'pair ::= name ws ":" ws verdict',
            'tiers ::= "{" ws ( tierpair ( ws "," ws tierpair )* ws )? "}"',
            'tierpair ::= name ws ":" ws tier',
            f"name ::= {name_rule}",
            f"verdict ::= {verdict_rule}",
            f"tier ::= {tier_rule}",
            "ws ::= [ \\t\\n]*",
        )
    )
