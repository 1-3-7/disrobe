def greet(name):
    msg = "hello, " + name
    print(msg)
    return len(msg)


def main():
    total = 0
    for who in ("alice", "bob", "carol"):
        total += greet(who)
    print("total chars:", total)
    return total


if __name__ == "__main__":
    main()
