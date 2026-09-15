local function fib(n)
  if n < 2 then
    return n
  end
  return fib(n - 1) + fib(n - 2)
end

local s = ""
for i = 1, 5 do
  s = s .. tostring(fib(i))
end

local nested = {a = {b = {c = 42}}}
local flag = true and false or true
local neg = -(3 + 4)
local len = #"abcdef"

print(s, nested.a.b.c, flag, neg, len, math.floor(3.7))
