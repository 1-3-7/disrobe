def main(c, d, e, b):
    out = []
    n1 = 0
    while n1 < 4 and ((e >= c // 2) and b > 9 or n1 == 0):
        n1 += 1
        try:
            out.append(n1)
        except ZeroDivisionError:
            pass
    try:
        a = c // ((d % 2) % 3)
        for i in range(0, 3):
            out.append(a + i)
    except ZeroDivisionError:
        out.append("zero")
    print(out)


main(4, 6, 0, 0)
main(4, 7, 9, 10)
