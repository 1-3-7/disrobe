name = "world"
items = [1, 2, 3]
summary = f"hello {name.upper()} count={len(items)}"
breakdown = f"items=[{', '.join(str(i) for i in items)}]"
print(summary)
print(breakdown)
