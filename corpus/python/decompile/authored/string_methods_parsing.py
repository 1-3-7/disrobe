HEADER_SEP = ": "


def parse_headers(raw):
    headers = {}
    for line in raw.splitlines():
        if not line.strip():
            break
        name, sep, value = line.partition(HEADER_SEP)
        if not sep:
            continue
        headers[name.strip().lower()] = value.strip()
    return headers


def parse_query(query):
    params = {}
    for pair in query.lstrip("?").split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        params.setdefault(key, []).append(value.replace("+", " "))
    return params


def slugify(title):
    cleaned = "".join(ch if ch.isalnum() else " " for ch in title.lower())
    return "-".join(cleaned.split())


def title_case(text, small=("a", "an", "of", "the")):
    words = text.split()
    out = []
    for index, word in enumerate(words):
        if index and word.lower() in small:
            out.append(word.lower())
        else:
            out.append(word.capitalize())
    return " ".join(out)


def wrap(text, width):
    lines = []
    current = ""
    for word in text.split():
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = current + " " + word if current else word
    if current:
        lines.append(current)
    return "\n".join(line.ljust(width) for line in lines)


def checks(text):
    return (
        text.startswith(("http://", "https://")),
        text.endswith(".py"),
        text.isdigit(),
        text.count("/"),
        text.find("://"),
        text.rfind("/"),
        text.upper().center(20, "."),
        text.encode("utf-8").hex(),
    )
