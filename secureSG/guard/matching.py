"""Aho-Corasick multi-pattern substring matcher.

Shared infrastructure: taint tracking searches outgoing arguments for tainted
values, and the SP3 screener searches untrusted content for known injection
signatures. Both are the same problem — find which of many patterns occur in a
text in a single O(n) pass — so the automaton lives here once.

Patterns are registered with an integer index; ``search`` returns the set of
indices whose patterns occur (as substrings) in the text.
"""

from collections import deque

_ROOT = 0


class AhoCorasick:
    """Multi-pattern substring matcher.

    Time complexity: ``search`` is O(n + matches) in the text length, after an
    O(sum of pattern lengths) build. Space complexity: O(sum of pattern lengths).
    """

    def __init__(self) -> None:
        self._goto: list[dict[str, int]] = [{}]
        self._fail: list[int] = [_ROOT]
        self._output: list[set[int]] = [set()]
        self._dirty = False

    def add(self, pattern: str, index: int) -> None:
        """Register ``pattern`` under ``index``. O(len(pattern))."""
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
        """Return the indices whose patterns occur in ``text``. O(n + matches)."""
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
