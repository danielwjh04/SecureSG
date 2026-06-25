"""Tests for field + substring taint tracking."""

from secureSG.guard.taint import SessionTaintStore, TaintLabel, TaintTier


def test_tiers_are_ordered() -> None:
    assert TaintTier.HIGH > TaintTier.MEDIUM > TaintTier.LOW


def test_scan_finds_registered_substring() -> None:
    store = SessionTaintStore()
    store.register("sk-secret-123", TaintLabel("read_secret", TaintTier.HIGH))
    labels = store.scan("here is the key: sk-secret-123 ok")
    assert TaintLabel("read_secret", TaintTier.HIGH) in labels


def test_scan_clean_text_returns_empty() -> None:
    store = SessionTaintStore()
    store.register("sk-secret-123", TaintLabel("read_secret", TaintTier.HIGH))
    assert store.scan("nothing sensitive here") == set()


def test_highest_tier_among_matches() -> None:
    store = SessionTaintStore()
    store.register("aaa", TaintLabel("read_file", TaintTier.MEDIUM))
    store.register("bbb", TaintLabel("read_secret", TaintTier.HIGH))
    assert store.highest_tier("xx aaa yy bbb") is TaintTier.HIGH
    assert store.highest_tier("only aaa") is TaintTier.MEDIUM
    assert store.highest_tier("clean") is None


def test_ingest_walks_nested_json() -> None:
    store = SessionTaintStore()
    store.ingest(
        {"data": {"secret": "topsecret"}, "list": ["xyz"]},
        TaintLabel("read_secret", TaintTier.HIGH),
    )
    assert store.highest_tier("contains topsecret") is TaintTier.HIGH
    assert store.highest_tier("contains xyz") is TaintTier.HIGH


def test_register_keeps_highest_tier_for_same_value() -> None:
    store = SessionTaintStore()
    store.register("dup", TaintLabel("read_file", TaintTier.LOW))
    store.register("dup", TaintLabel("read_secret", TaintTier.HIGH))
    assert store.highest_tier("dup") is TaintTier.HIGH


def test_empty_string_is_ignored() -> None:
    store = SessionTaintStore()
    store.register("", TaintLabel("read_secret", TaintTier.HIGH))
    assert store.scan("anything") == set()


def test_overlapping_patterns_all_match() -> None:
    store = SessionTaintStore()
    store.register("he", TaintLabel("a", TaintTier.LOW))
    store.register("she", TaintLabel("b", TaintTier.MEDIUM))
    store.register("hers", TaintLabel("c", TaintTier.HIGH))
    sources = {label.source_tool for label in store.scan("ushers")}
    assert sources == {"a", "b", "c"}


def test_scan_arguments_returns_per_field_tier() -> None:
    store = SessionTaintStore()
    store.register("sk-1", TaintLabel("read_secret", TaintTier.HIGH))
    fields = store.scan_arguments({"body": "the key is sk-1", "subject": "hello"})
    assert fields["body"] is TaintTier.HIGH
    assert "subject" not in fields


def test_scan_arguments_walks_nested_argument_values() -> None:
    store = SessionTaintStore()
    store.register("sk-1", TaintLabel("read_secret", TaintTier.HIGH))
    fields = store.scan_arguments({"payload": {"nested": ["sk-1"]}})
    assert fields["payload"] is TaintTier.HIGH


def test_ingest_ignores_non_string_scalars() -> None:
    store = SessionTaintStore()
    store.ingest(
        {"count": 5, "flag": True, "nil": None, "secret": "topsecret"},
        TaintLabel("read_secret", TaintTier.HIGH),
    )
    assert store.highest_tier("topsecret") is TaintTier.HIGH
    assert store.highest_tier("5 True None") is None


def test_reregister_with_lower_tier_keeps_higher() -> None:
    store = SessionTaintStore()
    store.register("dup", TaintLabel("read_secret", TaintTier.HIGH))
    store.register("dup", TaintLabel("read_file", TaintTier.LOW))
    assert store.highest_tier("dup") is TaintTier.HIGH
