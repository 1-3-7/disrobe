out = []
def main(k, t, c, d, e):
    if d in t:
        t.append(1)
    else:
        for j in k:
            try:
                t.append(5 // c)
            except ZeroDivisionError:
                t.append(0)
        t.append(9)
    out.append(t)
main([1, 2], [], 1, 0, 3)
main([1, 2], [0], 0, 0, 3)
print(out)
