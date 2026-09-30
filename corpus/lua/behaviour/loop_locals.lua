local t = {}
local b = 1
t[1] = b % 10
local n = 0
repeat
  n = n + 1
  b = (n - 6) % 1000
until n >= 2
print(b, t[1])

local c = 2
t[2] = c
for i = 1, 3 do
  if i > 1 then
    c = i * 4
  end
end
print(c)

local w = 0
t[3] = w
local k = 0
while k < 3 do
  k = k + 1
  w = k + 100
end
print(w)
