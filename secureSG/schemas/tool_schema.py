"""Minimal MCP tool descriptor used by Warden discovery (and the SP5 proxy)."""

from pydantic import BaseModel, ConfigDict


class ToolSchema(BaseModel):
    """A tool's advertised name and description from its MCP schema."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
