def greet(name):
    return "hello, " + name


def total(values):
    acc = 0
    for v in values:
        acc += v
    return acc


print(greet("disrobe"))
print(total([1, 2, 3, 4, 5]))
for i in range(3):
    print("line", i, i * i)
