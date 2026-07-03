def parse(version_number):
    try:
        if len(version_number) != 2:
            raise ValueError
        if any(not component.isdigit() for component in version_number):
            raise ValueError("non digit in version")
        if any(len(component) > 10 for component in version_number):
            raise ValueError("unreasonable length version")
        result = int(version_number[0]), int(version_number[1])
    except (ValueError, IndexError):
        return None
    return result
