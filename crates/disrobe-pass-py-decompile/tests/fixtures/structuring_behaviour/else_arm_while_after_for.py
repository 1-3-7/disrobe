def main(e, c, d):
    out = []
    t = []
    n1 = 0
    while n1 < 2 and (11 in t or n1 == 0):
        n1 += 1
        for i3 in range(3, 5):
            b = sum(x * d for x in range(4) if x % 2 == 0) + i3
        if e + c != c:
            if c % 2 > b:
                out.append("odd")
        else:
            n6 = 0
            while n6 < 2 and (10 < b % 3 and d > 3 or n6 == 0):
                n6 += 1
                out.append(n6)
            else:
                out.append("else")
    print(out)


main(2, 5, 5)
main(0, 5, 5)
main(0, 5, 1)
