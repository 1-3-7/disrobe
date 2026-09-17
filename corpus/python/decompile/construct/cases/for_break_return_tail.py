def h(rows, key):
    chosen = None
    for row in rows:
        if row == key:
            chosen = row
            break
    return chosen
