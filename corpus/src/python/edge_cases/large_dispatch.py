from functools import singledispatch


@singledispatch
def visit(node) -> str:
    return f"unknown:{type(node).__name__}"


@visit.register
def _(node: int) -> str:
    return f"int:{node}"


@visit.register
def _(node: str) -> str:
    return f"str:{node}"


@visit.register
def _(node: list) -> str:
    return "list:[" + ",".join(visit(item) for item in node) + "]"


@visit.register
def _(node: dict) -> str:
    keys = sorted(node)
    return "dict:{" + ",".join(f"{k}={visit(node[k])}" for k in keys) + "}"


print(visit({"a": 1, "b": [2, "three", {"c": 4}]}))
