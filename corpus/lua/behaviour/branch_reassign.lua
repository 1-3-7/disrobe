local b = 7
local c = 0
if c == 0 then
  c = 1
else
  b = (c + 1) % 1000
  b = 5
  c = b
end
print(b, c)

local x = 3
local n = 0
while n < 2 do
  n = n + 1
  if n == 2 then
    x = n * 10
    x = n + 20
    print(x)
  end
end
print(x)
