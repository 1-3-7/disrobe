local function add(a, b)
  return a + b
end
local total = 0
for i = 1, 5 do
  total = total + add(i, i * 2)
end
print("total=" .. total)
local t = { x = 10, y = 20 }
print(t.x + t.y)
local s = "abc"
print(#s, s:upper())
