import sys


def main(argv):
    total = 0
    for item in argv:
        total += len(item)
    return total


if __name__ == "__main__":
    result = main(sys.argv)
    print(result)
