NEIGHBOURS = ((-1, 0), (1, 0), (0, -1), (0, 1))


def make_grid(rows, cols, fill=0):
    grid = []
    for r in range(rows):
        row = []
        for c in range(cols):
            row.append(fill + r * cols + c)
        grid.append(row)
    return grid


def transpose(grid):
    if not grid:
        return []
    out = [[None] * len(grid) for _ in grid[0]]
    for r, row in enumerate(grid):
        for c, value in enumerate(row):
            out[c][r] = value
    return out


def count_islands(grid):
    rows = len(grid)
    cols = len(grid[0]) if rows else 0
    seen = set()
    islands = 0
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == 0 or (r, c) in seen:
                continue
            islands += 1
            stack = [(r, c)]
            while stack:
                y, x = stack.pop()
                if (y, x) in seen:
                    continue
                seen.add((y, x))
                for dy, dx in NEIGHBOURS:
                    ny, nx = y + dy, x + dx
                    if 0 <= ny < rows and 0 <= nx < cols and grid[ny][nx]:
                        stack.append((ny, nx))
    return islands


def multiply(a, b):
    size = len(b[0])
    result = [[0] * size for _ in a]
    for i in range(len(a)):
        for j in range(size):
            acc = 0
            for k in range(len(b)):
                acc += a[i][k] * b[k][j]
            result[i][j] = acc
    return result
