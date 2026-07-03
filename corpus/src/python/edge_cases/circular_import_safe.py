import importlib
import sys


def import_under_alias(module_name: str, alias: str) -> object:
    mod = importlib.import_module(module_name)
    sys.modules[alias] = mod
    return mod


json_mod = import_under_alias("json", "_json_alias")
print(json_mod.dumps({"k": [1, 2, 3]}))
print("_json_alias" in sys.modules)
