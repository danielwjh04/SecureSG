"""Field- and substring-level taint tracking.

A transparent proxy sees only tool I/O, not the agent's internal string ops, so
taint is tracked at the boundary: tainted values produced by high-risk tools are
registered in a per-session store, and every outgoing call's arguments are scanned
for those values with an Aho-Corasick automaton (O(n) multi-pattern match). A match
taints the field at the highest matched tier — catching a secret embedded as a
substring of a larger, benign-looking value.
"""

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum

from secureSG.schemas.tool_call import JsonValue

_ROOT = 0


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


class _AhoCorasick:
    """Multi-pattern substring matcher.

    Time complexity: search is O(n + matches) in the text length, after an
    O(sum of pattern lengths) build. Space complexity: O(sum of pattern lengths).
    """

    def __init__(self) -> None:
        self._goto: list[dict[str, int]] = [{}]
        self._fail: list[int] = [_ROOT]
        self._output: list[set[int]] = [set()]
        self._dirty = False

    def add(self, pattern: str, index: int) -> None:
        node = _ROOT
        for char in pattern:
            nxt = self._goto[node].get(char)
            if nxt is None:
                nxt = len(self._goto)
                self._goto.append({})
                self._fail.append(_ROOT)
                self._output.append(set())
                self._goto[node][char] = nxt
            node = nxt
        self._output[node].add(index)
        self._dirty = True

    def _build(self) -> None:
        queue: deque[int] = deque()
        for child in self._goto[_ROOT].values():
            self._fail[child] = _ROOT
            queue.append(child)
        while queue:
            node = queue.popleft()
            for char, nxt in self._goto[node].items():
                queue.append(nxt)
                fallback = self._fail[node]
                while fallback != _ROOT and char not in self._goto[fallback]:
                    fallback = self._fail[fallback]
                self._fail[nxt] = self._goto[fallback].get(char, _ROOT)
                self._output[nxt] |= self._output[self._fail[nxt]]
        self._dirty = False

    def search(self, text: str) -> set[int]:
        if self._dirty:
            self._build()
        matches: set[int] = set()
        node = _ROOT
        for char in text:
            while node != _ROOT and char not in self._goto[node]:
                node = self._fail[node]
            node = self._goto[node].get(char, _ROOT)
            matches |= self._output[node]
        return matches


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
        self._automaton = _AhoCorasick()
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
