def f(matrix, needle):
    for i, row in enumerate(matrix):
        for j, cell in enumerate(row):
            if cell == needle:
                return (i, j)
    return None
