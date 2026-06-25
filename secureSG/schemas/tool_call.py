"""Pydantic schemas for JSON-RPC 2.0 tool calls and tool results.

Every inbound tool call is validated against ``ToolCallSchema`` before any policy
logic runs; a validation failure becomes a BLOCK verdict, never an unhandled
exception. ``ToolResult`` carries arbitrary tool output, which the taint tracker
walks to register tainted values.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

type JsonValue = (
    str | int | float | bool | None | dict[str, JsonValue] | list[JsonValue]
)


class ToolCallParams(BaseModel):
    """The ``params`` object of a JSON-RPC ``tools/call`` request."""

    model_config = ConfigDict(frozen=True)

    name: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class ToolCallSchema(BaseModel):
    """A validated JSON-RPC 2.0 tool call."""

    model_config = ConfigDict(frozen=True)

    jsonrpc: Literal["2.0"]
    id: int | str
    method: str
    params: ToolCallParams

    @property
    def tool_name(self) -> str:
        """The name of the tool being invoked."""
        return self.params.name

    @property
    def arguments(self) -> dict[str, JsonValue]:
        """The arguments passed to the tool."""
        return self.params.arguments


class ToolResult(BaseModel):
    """The output of a tool invocation, used as a taint source."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    result: JsonValue
