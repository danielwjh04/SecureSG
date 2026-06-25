"""Tests for JSON-RPC interception: parse, extract, and txn-id derivation."""

from typing import Any

from secureSG.guard.interceptor import (
    derive_result_transaction_id,
    derive_transaction_id,
    extract_result,
    parse_call,
)


def _raw_call(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def test_parse_call_accepts_valid_envelope() -> None:
    call = parse_call(_raw_call("read_secret", {"k": "v"}))
    assert call is not None
    assert call.tool_name == "read_secret"
    assert call.arguments == {"k": "v"}


def test_parse_call_rejects_malformed_returns_none() -> None:
    assert parse_call({"not": "a jsonrpc call"}) is None


def test_extract_result_wraps_result_payload() -> None:
    response = {"jsonrpc": "2.0", "id": 1, "result": {"content": "hello"}}
    result = extract_result(response, "scrape_page")
    assert result is not None
    assert result.tool_name == "scrape_page"
    assert result.result == {"content": "hello"}


def test_extract_result_accepts_string_payload() -> None:
    result = extract_result({"jsonrpc": "2.0", "id": 1, "result": "ok"}, "send_email")
    assert result is not None
    assert result.result == "ok"


def test_extract_result_on_jsonrpc_error_returns_none() -> None:
    response = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "x"}}
    assert extract_result(response, "scrape_page") is None


def test_extract_result_on_malformed_returns_none() -> None:
    assert extract_result({"jsonrpc": "2.0", "id": 1}, "scrape_page") is None


def test_extract_result_on_non_json_payload_returns_none() -> None:
    # A result that is not a valid JsonValue must fail closed, not raise.
    assert extract_result({"result": object()}, "scrape_page") is None


def test_transaction_id_is_stable_across_key_order() -> None:
    a = derive_transaction_id("s1", 1, {"a": 1, "b": 2})
    b = derive_transaction_id("s1", 1, {"b": 2, "a": 1})
    assert a == b


def test_transaction_id_differs_on_arguments() -> None:
    a = derive_transaction_id("s1", 1, {"a": 1})
    b = derive_transaction_id("s1", 1, {"a": 2})
    assert a != b


def test_transaction_id_differs_on_session() -> None:
    a = derive_transaction_id("s1", 1, {"a": 1})
    b = derive_transaction_id("s2", 1, {"a": 1})
    assert a != b


def test_result_transaction_id_is_derived_distinct_and_stable() -> None:
    call_txn = derive_transaction_id("s1", 1, {"a": 1})
    result_txn = derive_result_transaction_id(call_txn)
    assert result_txn != call_txn
    assert derive_result_transaction_id(call_txn) == result_txn
