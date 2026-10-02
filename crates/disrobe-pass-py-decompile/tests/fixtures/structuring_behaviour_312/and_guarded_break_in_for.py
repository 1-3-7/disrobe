def flat(a, d):
    c = 8
    for j in range(3):
        c = c + j
        if c != a and d > 2:
            break
    print("flat", c)


def nested(a, d):
    c = 8
    for i in range(2):
        for j in range(3):
            c = c + j
            if c != a and d > 2:
                break
    print("nested", c)


flat(4, 4)
flat(9, 1)
nested(4, 4)
nested(9, 1)
