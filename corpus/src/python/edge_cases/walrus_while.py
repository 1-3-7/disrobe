import io


def read_chunks(data: bytes, size: int) -> list[bytes]:
    stream = io.BytesIO(data)
    chunks: list[bytes] = []
    while chunk := stream.read(size):
        chunks.append(chunk)
    return chunks


print(read_chunks(b"abcdefghij", 3))
print(read_chunks(b"", 4))
