local a = 1
local b = 2
local function f() return b end
print(a, b, f())
b = 7
print(a, b, f())
local function outer()
  local function inner() return a + b end
  return inner()
end
print(a, b, outer())
local function bump() b = b + 1 return b end
print(bump(), bump(), a, b)
