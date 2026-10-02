out = []


def emit(v):
    out.append(str(v))


def main():
    t = []
    a = 0
    b = 4
    d = 7
    for i4 in range(2, 6):
        c = (a + i4) % 1000
        try:
            e = d % 1000
            emit(len([x for x in t if x > 15]))
            t.append((d * c) % 97)
            if not (d != (a % 7)):
                break
            emit(len([x for x in t if x > a]))
            for i6 in range(2, 5):
                a %= 1000
                b += (d % 8)
                b %= 1000
                d += (12 // 4)
                d %= 1000
                c = (t[1] if len(t) > 1 else a)
        except ZeroDivisionError:
            emit("zero")
    emit(t)


main()
print(" ".join(out))
