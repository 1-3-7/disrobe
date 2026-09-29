class ConfigError(Exception):
    pass


class MissingKey(ConfigError):
    def __init__(self, key):
        super().__init__("missing key: " + key)
        self.key = key


def parse_port(text):
    try:
        port = int(text)
    except ValueError:
        return None
    except TypeError as exc:
        raise ConfigError("port must be text") from exc
    else:
        if not 0 < port < 65536:
            return None
        return port


def load_setting(mapping, key, default=None):
    try:
        try:
            value = mapping[key]
        except KeyError:
            if default is None:
                raise MissingKey(key)
            value = default
        try:
            return value.strip()
        except AttributeError:
            return value
    except MissingKey as missing:
        return "<" + missing.key + ">"


def safe_divide(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return float("inf") if a > 0 else float("-inf") if a < 0 else float("nan")
    except (TypeError, OverflowError) as exc:
        return str(exc)


def swallow_everything(func, *args):
    try:
        return func(*args)
    except:
        return None


def rethrow_with_note(func):
    try:
        func()
    except LookupError:
        raise
    except Exception as exc:
        raise RuntimeError("wrapped") from exc
