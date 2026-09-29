def mix(left, right, shift):
    total = left + right
    scaled = total * 3 - right
    ratio = scaled / (right or 1)
    whole = scaled // 7
    rest = scaled % 7
    power = left ** 2
    bits = (left & 0xF0) | (right ^ 0x0F)
    moved = (bits << shift) >> 1
    return total, scaled, ratio, whole, rest, power, bits, moved


values = mix(12, 5, 2)
print(values)
