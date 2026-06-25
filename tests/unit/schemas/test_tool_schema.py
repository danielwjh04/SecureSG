"""Tests for the minimal MCP tool descriptor."""

import pytest
from pydantic import ValidationError

from secureSG.schemas.tool_schema import ToolSchema


def test_tool_schema_holds_fields() -> None:
    tool = ToolSchema(name="scrape_page", description="fetch a web page by URL")
    assert tool.name == "scrape_page"
    assert tool.description == "fetch a web page by URL"


def test_tool_schema_is_frozen() -> None:
    tool = ToolSchema(name="x", description="y")
    with pytest.raises(ValidationError):
        tool.name = "z"  # type: ignore[misc]  # reason: testing frozen
