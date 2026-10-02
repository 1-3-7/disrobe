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



in_for(1, 2)
in_for(0, 2)
