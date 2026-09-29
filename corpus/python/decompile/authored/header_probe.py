def checksum(data):
    total = 0
    for index, value in enumerate(data):
        total = (total * 31 + value + index) & 0xFFFFFFFF
    return total


print(checksum(b"authored header probe seven eight"))
# 0066709
