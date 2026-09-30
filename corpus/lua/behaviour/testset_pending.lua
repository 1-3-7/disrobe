local t = {}
local b = 5
local c = 2
c = (t[2] or (b - c))
print(c)

local calls = 0
local function f(x)
  calls = calls + 1
  t[0] = nil
  return x + 5
end
t[0] = 3
local a = 1
a = f(a)
a = (t[0] or (a - a))
print(a, calls)

local d = 4
d = (t[1] and d) or (d * 3)
print(d)
