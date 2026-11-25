# -*- coding: utf-8 -*-
"""Shared parameter parsing helpers for Bintra MCP tool mixins."""

from typing import Any


def parse_int_arg(value: Any, field_name: str) -> int:
    """Parses decimal or hex (`0x...`) integer inputs strictly with clear context."""
    if isinstance(value, bool):
        raise ValueError(f"Invalid integer/hex address for '{field_name}': {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError(f"Empty integer/hex address for '{field_name}'.")
        try:
            return int(text, 0)
        except ValueError as exc:
            raise ValueError(f"Invalid integer/hex address for '{field_name}': {value!r}") from exc
    raise ValueError(f"Invalid integer/hex address for '{field_name}': {value!r}")
