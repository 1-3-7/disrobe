local function add(a, b)
  return a + b
end

local x = 10
local y = 20
print(add(x, y))

local t = {1, 2, 3}
local sum = 0
for i = 1, #t do
  sum = sum + t[i]
end
print(sum)

if sum > 5 then
  print("big")
else
  print("small")
end
