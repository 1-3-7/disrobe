def main(a, b):
    for i in range(3):
        if a:
            print("a", i)
        elif b:
            pass
        else:
            try:
                print("t", i, 6 // (i - 1))
            except ZeroDivisionError:
                pass


main(0, 0)
main(1, 0)
main(0, 1)
