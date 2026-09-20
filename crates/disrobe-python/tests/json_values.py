from __future__ import annotations

from typing import Union

JsonScalar = Union[str, int, float, bool, None]
JsonValue = Union[JsonScalar, list["JsonValue"], dict[str, "JsonValue"]]


def json_array(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def json_object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value
