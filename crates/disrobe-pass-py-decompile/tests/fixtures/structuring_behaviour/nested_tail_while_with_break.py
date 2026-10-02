def run(a, b, e):
    n2 = 0
    n3 = 0
    while n2 < 4 and a:
        n2 += 1
        while n3 < 3 and b:
            n3 += 1
            if e:
                break
    return n2, n3


print(run(True, True, False), run(True, True, True), run(False, True, True))
