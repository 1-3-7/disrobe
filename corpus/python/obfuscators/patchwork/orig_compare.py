def chain(n):
    r = []
    if 0 < n <= 100:
        r.append('mid')
    if n == 5 or n != 6:
        r.append('eqchk')
    if not (n > 1000):
        r.append('small')
    return r


print(chain(5))
print(chain(500))
