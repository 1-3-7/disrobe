def main(t, a, d):
    out = []
    for i in range(2, 5):
        if 3 in t:
            out.append("x")
        elif a > 1 and d > 1:
            try:
                out.append(a // (i - 3))
            except ZeroDivisionError:
                out.append("zero")
    print(out)


main([3], 2, 2)
main([], 2, 2)
main([], 0, 2)
main([], 2, 0)
