def classify(n):
    total = 0
    for i in range(n):
        if i % 2 == 0:
            total += i
        else:
            total -= 1
    if total > 10:
        return "big"
    return "small"


print(classify(6))
