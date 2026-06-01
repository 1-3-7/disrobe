stream = [1, 4, 9, 16, 25, 36, 49, 64, 81, 100]
total_pred = lambda xs, t=[0]: (t.__setitem__(0, t[0] + sum(xs)), t[0])[1]
print(total_pred(stream))


def take_until(iterable, *, stop):
    out = []
    for item in iterable:
        if (last := item) > stop:
            break
        out.append(last)
    return out


print(take_until(stream, stop=30))
