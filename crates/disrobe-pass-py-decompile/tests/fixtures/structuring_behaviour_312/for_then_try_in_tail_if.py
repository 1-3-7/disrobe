def main(c, a):
    print("start", c)
    if c < 0:
        for i in range(2):
            if c > a:
                print(i)
        try:
            if a != 8:
                print("x", a // (c + 1))
        except ZeroDivisionError:
            pass


main(1, 2)
main(-1, 2)
main(-3, -5)
