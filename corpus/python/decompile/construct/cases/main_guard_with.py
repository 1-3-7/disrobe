import sys


def _emit(text):
    print(text)


if __name__ == "__main__":
    with open(sys.argv[1]) as handle:
        _emit(handle.read())
