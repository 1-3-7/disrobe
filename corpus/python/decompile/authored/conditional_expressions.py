THRESHOLDS = {"cold": 5, "warm": 20, "hot": 30}


def plural(word, count):
    return word if count == 1 else word + "s"


def weather(temp):
    return "freezing" if temp < 0 else "cold" if temp < THRESHOLDS["cold"] else "warm" if temp < THRESHOLDS["hot"] else "hot"


def abs_diff(a, b):
    return a - b if a > b else b - a


def pick(values, use_max):
    return (max if use_max else min)(values)


def clamp_all(values, low, high):
    return [low if v < low else high if v > high else v for v in values]


def summarize(items):
    count = len(items)
    header = "no items" if not count else "one item" if count == 1 else f"{count} items"
    tail = (", ".join(items) if count < 4 else ", ".join(items[:3]) + ", ...") if count else ""
    return header + (": " + tail if tail else "")


def safe_ratio(num, den):
    return num / den if den else float("inf") if num else 0.0


def toggle(state):
    state["on"] = False if state.get("on") else True
    return state


def fizzbuzz(n):
    return "FizzBuzz" if n % 15 == 0 else "Fizz" if n % 3 == 0 else "Buzz" if n % 5 == 0 else str(n)


def call_or_value(obj):
    return obj() if callable(obj) else obj
