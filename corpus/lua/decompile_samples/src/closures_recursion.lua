local function make_counter()
  local count = 0
  return function()
    count = count + 1
    return count
  end
end
local c = make_counter()
print(c(), c(), c())

local function fib(n)
  if n < 2 then
    return n
  end
  return fib(n - 1) + fib(n - 2)
end
print(fib(10))

local t = { 3, 1, 4, 1, 5, 9, 2, 6 }
table.sort(t)
print(table.concat(t, ","))

local function maxof(a, b)
  return a > b and a or b
end
print(maxof(3, 8), maxof(10, 2))

local str = "Hello, World"
print(str:lower(), str:sub(1, 5), str:len())
print(string.format("%d-%s-%0.2f", 42, "x", 3.14159))

local function multi()
  return 1, 2, 3
end
local a, b, cc = multi()
print(a + b + cc)
