def proc(data):
    out = []
    n = len(data)
    if (half := n // 2) > 0:
        out.append(half)
    out.append(data[1:3])
    out.append(data[::2])
    d = {'a': 1, 'b': 2}
    s = {1, 2, 3}
    t = (n, half)
    return out, d, s, t


print(proc([10, 20, 30, 40, 50]))
