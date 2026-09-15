def f(seq):
    return seq[:] + seq[1:] + seq[:-1] + seq[::2] + seq[::-1]
