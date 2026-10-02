def in_for(e, b):
    out = []
    for k in range(2):
        if e:
            out.append("e")
        else:
            n = 0
            while n < 2:
                n += 1
                out.append(n)
    print(out)


def in_while(e, c, b):
    out = []
    n0 = 0
    while n0 < 2:
        n0 += 1
        if e != c:
            out.append("ne")
        else:
            n = 0
            while n < 2 and (b > 3 or n == 0):
                n += 1
                out.append(n)
    print(out)


in_for(1, 2)
in_for(0, 2)
in_while(1, 2, 1)
in_while(1, 1, 20)
in_while(1, 1, 1)
