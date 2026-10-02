def main(a):
    out = []
    for i in range(1, 4):
        try:
            b = 12 // ((a * 16) % 97 % 3)
            out.append(b)
        finally:
            pass
        out.append(i)
    print(out)


main(1)
main(2)
