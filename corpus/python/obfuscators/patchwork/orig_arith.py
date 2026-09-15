def calc(a, b):
    x = a + b * 2 - 1
    y = x % 7
    z = (a ** 2) // 3
    return x + y + z + (a << 1) + (b >> 1) + (a | b) + (a & b) + (a ^ b)


print(calc(10, 4))
print(calc(7, 3))
