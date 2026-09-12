name = "world"
parts = ["a", "b", "c"]
nested = f"hi {f'{name!r} {f"inner {name.upper()!s}"}'} end"
quoted = f"{'plain'} {f'{'mid'} {f"{name}"}'}"
spec = f"{name:>{len(name) + 2}.{len(name)}}"
joined = f"[{', '.join(f'x={p!r}' for p in parts)}]"
mixed = f"""triple {f"single {name}"} and {f"apos {parts[0]!r}"}"""
print(nested, quoted, spec, joined, mixed)
