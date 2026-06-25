"""Tests for the JSON-RPC tool-call and tool-result schemas."""

from typing import Any

import pytest
from pydantic import ValidationError

from secureSG.schemas.tool_call import ToolCallSchema, ToolResult


def valid_call(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": "a@b.com"}},
    }
    base.update(overrides)
    return base


def test_valid_tool_call_parses() -> None:
    call = ToolCallSchema.model_validate(valid_call())
    assert call.tool_name == "send_email"
    assert call.arguments == {"to": "a@b.com"}
    assert call.method == "tools/call"


def test_rejects_wrong_jsonrpc_version() -> None:
    with pytest.raises(ValidationError):
        ToolCallSchema.model_validate(valid_call(jsonrpc="1.0"))


def test_rejects_missing_params() -> None:
    bad = valid_call()
    del bad["params"]
    with pytest.raises(ValidationError):
        ToolCallSchema.model_validate(bad)


def test_arguments_default_to_empty_dict() -> None:
    call = ToolCallSchema.model_validate(valid_call(params={"name": "list_dir"}))
    assert call.arguments == {}


def test_tool_call_is_immutable() -> None:
    call = ToolCallSchema.model_validate(valid_call())
    with pytest.raises(ValidationError):
        call.method = "tools/list"  # type: ignore[misc]  # reason: testing frozen


def test_tool_result_holds_nested_result() -> None:
    result = ToolResult(tool_name="read_secret", result={"secret": "sk-123"})
    assert result.tool_name == "read_secret"
    assert result.result == {"secret": "sk-123"}


def test_tool_result_accepts_string_and_list() -> None:
    assert ToolResult(tool_name="scrape_page", result="hello").result == "hello"
    assert ToolResult(tool_name="scrape_page", result=["a", "b"]).result == ["a", "b"]
