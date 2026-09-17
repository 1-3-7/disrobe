def f(buf, d, k, n):
    buf[-1] += n
    buf[0] -= n
    d[k] *= 2
    d[k] //= 3
    buf[k + 1] |= n
    return buf, d
