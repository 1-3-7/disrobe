def main(c, d):
    try:
        print("start", c)
        if 6 < d:
            b = (14 // 4) or 8
            print("b", b, 12 // c)
    except ZeroDivisionError:
        print("zero")


main(1, 9)
main(0, 9)
main(5, 2)
