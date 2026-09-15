GREETING_PREFIX = "disrobe-enc"
MAGIC_CONSTANT = 4242


def greet(name):
    return f"{GREETING_PREFIX}: hello {name}"


if __name__ == "__main__":
    print(greet("encrypted-world"))
    print(MAGIC_CONSTANT)
