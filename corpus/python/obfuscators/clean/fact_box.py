def fact(n):
    if n <= 1:
        return 1
    return n * fact(n - 1)
class Box:
    def __init__(self, v):
        self.v = v
    def double(self):
        return self.v * 2
def main():
    b = Box(fact(5))
    print(b.double())
if __name__ == "__main__":
    main()