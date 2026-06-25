"""Field- and substring-level taint tracking.

A transparent proxy sees only tool I/O, not the agent's internal string ops, so
taint is tracked at the boundary: tainted values produced by high-risk tools are
registered in a per-session store, and every outgoing call's arguments are scanned
for those values with an Aho-Corasick automaton (O(n) multi-pattern match). A match
taints the field at the highest matched tier — catching a secret embedded as a
substring of a larger, benign-looking value.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum

from secureSG.guard.matching import AhoCorasick
from secureSG.schemas.tool_call import JsonValue


class TaintTier(IntEnum):
    """Risk tier of a tainted value. Ordered so the highest tier wins."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True, slots=True)
class TaintLabel:
    """Provenance of a tainted value: the tool that produced it and its tier."""

    source_tool: str
    tier: TaintTier


def _iter_strings(value: JsonValue) -> Iterator[str]:
    """Yield every string leaf in a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


class SessionTaintStore:
    """Per-session registry of tainted values with substring scanning."""

    def __init__(self) -> None:
        self._automaton = AhoCorasick()
        self._labels: list[TaintLabel] = []
        self._index_of: dict[str, int] = {}

    def register(self, value: str, label: TaintLabel) -> None:
        """Register a tainted string value (empty strings are ignored).

        Re-registering the same value keeps the highest tier seen.
        Time complexity: O(len(value)). Space complexity: O(len(value)).
        """
        if not value:
            return
        existing = self._index_of.get(value)
        if existing is not None:
            if label.tier > self._labels[existing].tier:
                self._labels[existing] = label
            return
        index = len(self._labels)
        self._labels.append(label)
        self._index_of[value] = index
        self._automaton.add(value, index)

    def ingest(self, value: JsonValue, label: TaintLabel) -> None:
        """Register every string leaf of a tool result under one label.

        Time complexity: O(total string length). Space complexity: O(same).
        """
        for leaf in _iter_strings(value):
            self.register(leaf, label)

    def scan(self, text: str) -> set[TaintLabel]:
        """Return the taint labels whose values occur in ``text``.

        Time complexity: O(len(text) + matches). Space complexity: O(matches).
        """
        return {self._labels[index] for index in self._automaton.search(text)}

    def highest_tier(self, text: str) -> TaintTier | None:
        """Return the highest taint tier present in ``text``, or ``None``."""
        labels = self.scan(text)
        if not labels:
            return None
        return max(label.tier for label in labels)

    def scan_arguments(
        self, arguments: dict[str, JsonValue]
    ) -> dict[str, TaintTier]:
        """Return the highest taint tier found in each tainted argument field.

        Clean fields are omitted from the result.
        Time complexity: O(total argument string length). Space complexity: O(fields).
        """
        tainted: dict[str, TaintTier] = {}
        for field, value in arguments.items():
            tiers = [
                tier
                for leaf in _iter_strings(value)
                if (tier := self.highest_tier(leaf)) is not None
            ]
            if tiers:
                tainted[field] = max(tiers)
        return tainted
