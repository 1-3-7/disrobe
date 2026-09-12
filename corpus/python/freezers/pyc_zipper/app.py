import os
import sys

SECRET = 'disrobe-pyc-zipper-oracle'

def greet(name):
    total = 0
    for i in range(len(name)):
        total += ord(name[i]) * (i + 1)
    return f'hello {name} {total} {SECRET}'

def main():
    args = sys.argv[1:] or ['world']
    for a in args:
        print(greet(a))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
