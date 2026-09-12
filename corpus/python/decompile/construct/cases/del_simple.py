def f(store):
    temp = dict(store)
    del temp["key"]
    return len(temp)
