def in_for(e, b):
    out = []
    for n in range(2):
        if e == 18:
            out.append(1)
        elif e >= 17 or b == 7:
            out.append(2)
    print(out)


def in_while(e, b):
    out = []
    n = 0
    while n < 2:
        n += 1
        if e == 18 and b > 1:
            out.append(1)
        elif e >= 17 or b == 7:
            out.append(2)
    print(out)


for args in ((18, 2), (17, 0), (0, 7), (0, 0)):
    in_for(*args)
    in_while(*args)
