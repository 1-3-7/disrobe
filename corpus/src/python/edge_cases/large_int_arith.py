def power_tower(base: int, height: int) -> int:
    result = 1
    for _ in range(height):
        result = base**result
        if result.bit_length() > 4096:
            break
    return result


def bit_manipulations(value: int) -> tuple[int, int, int, int]:
    rotated = ((value << 7) | (value >> (64 - 7))) & ((1 << 64) - 1)
    masked = value & 0xDEAD_BEEF_CAFE_BABE
    xored = value ^ 0xFFFF_FFFF_FFFF_FFFF
    popcount = bin(value).count("1")
    return rotated, masked, xored, popcount


print(power_tower(2, 5).bit_length())
print(bit_manipulations(0x0123_4567_89AB_CDEF))
