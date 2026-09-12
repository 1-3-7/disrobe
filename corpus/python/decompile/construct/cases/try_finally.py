def f(resource):
    try:
        resource.append(1)
        return sum(resource)
    finally:
        resource.clear()
