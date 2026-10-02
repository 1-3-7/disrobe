def main(e, d, c):
    out = []
    n1 = 0
    while n1 < 4:
        n1 += 1
        if e > 2:
            try:
                e = c // ((d - e) % 3)
            except ZeroDivisionError:
                pass
            finally:
                out.append("fin")
        pass
    try:
        out.append(d)
    except ZeroDivisionError:
        pass
    print(out)


main(5, 5, 3)
main(5, 6, 3)
