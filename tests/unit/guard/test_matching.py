"""Tests for the shared Aho-Corasick multi-pattern matcher."""

from secureSG.guard.matching import AhoCorasick


def test_finds_single_pattern() -> None:
    automaton = AhoCorasick()
    automaton.add("secret", 0)
    assert automaton.search("here is a secret value") == {0}


def test_no_match_returns_empty() -> None:
    automaton = AhoCorasick()
    automaton.add("secret", 0)
    assert automaton.search("nothing here") == set()


def test_overlapping_patterns_all_match() -> None:
    automaton = AhoCorasick()
    automaton.add("he", 0)
    automaton.add("she", 1)
    automaton.add("hers", 2)
    assert automaton.search("ushers") == {0, 1, 2}


def test_multiple_distinct_patterns() -> None:
    automaton = AhoCorasick()
    automaton.add("foo", 10)
    automaton.add("bar", 20)
    assert automaton.search("xx foo yy bar") == {10, 20}


def test_search_with_no_patterns_is_empty() -> None:
    assert AhoCorasick().search("anything") == set()


def test_rebuilds_after_add_between_searches() -> None:
    automaton = AhoCorasick()
    automaton.add("aaa", 0)
    assert automaton.search("aaa") == {0}
    automaton.add("bbb", 1)
    assert automaton.search("aaa bbb") == {0, 1}
