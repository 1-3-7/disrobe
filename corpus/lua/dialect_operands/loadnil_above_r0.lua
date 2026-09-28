local a, b, c = 1, 2, 3
c = nil
print(a, b, c)
local d, e, f
print(a, b, c, d, e, f)
b = nil
print(a, b, c)
local g, h = 4, 5
g, h = nil, nil
print(a, g, h)
