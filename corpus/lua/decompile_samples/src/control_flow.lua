local function classify(n)
  if n < 0 then
    return "neg"
  elseif n == 0 then
    return "zero"
  else
    return "pos"
  end
end
print(classify(-5), classify(0), classify(7))
local i = 1
local acc = 0
while i <= 10 do
  acc = acc + i
  i = i + 1
end
print("acc", acc)
local list = {}
for k = 1, 4 do
  list[k] = k * k
end
local sum = 0
for _, v in ipairs(list) do
  sum = sum + v
end
print("sum", sum)
local function variadic(...)
  local t = {...}
  return #t
end
print(variadic(1, 2, 3, 4, 5))
