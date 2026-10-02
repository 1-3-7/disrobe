def with_finally(t):
    for i in range(3):
        if 3 in t:
            print("a", i)
        elif 1 in t:
            try:
                print("z", i)
            finally:
                print("f", i)


def with_except(t):
    for i in range(3):
        if 3 in t:
            print("a", i)
        elif 1 in t:
            try:
                print("z", i, 4 // (i - 1))
            except ZeroDivisionError:
                print("zero", i)


for arg in ([3], [1], []):
    with_finally(arg)
    with_except(arg)
