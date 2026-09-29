local Animal = {}
Animal.__index = Animal
function Animal.new(name, sound) return setmetatable({name = name, sound = sound}, Animal) end
function Animal:speak() return self.name .. " says " .. self.sound end
local Dog = setmetatable({}, {__index = Animal})
Dog.__index = Dog
function Dog.new(name) local d = Animal.new(name, "woof") return setmetatable(d, Dog) end
function Dog:fetch(n) local out = {} for i = 1, n do out[#out + 1] = self.name .. i end return table.concat(out, "+") end
local d = Dog.new("rex")
print(d:speak(), d:fetch(3))

local fns = {}
for i = 1, 3 do fns[i] = function() return i * 10 end end
print(fns[1](), fns[2](), fns[3]())

local function stats(...)
  local n = select("#", ...)
  local sum, mx = 0, -math.huge
  for i = 1, n do
    local v = select(i, ...)
    sum = sum + v
    if v > mx then mx = v end
  end
  return sum, mx, n > 0 and sum / n or 0
end
print(stats(4, 9, 2), stats())

local function classify(x)
  if x < 0 then return "neg"
  elseif x == 0 then return "zero"
  elseif x < 10 and x % 2 == 0 then return "small-even"
  elseif x < 10 then return "small-odd"
  else return "big" end
end
local parts = {}
for _, v in ipairs({-3, 0, 4, 7, 12}) do parts[#parts + 1] = classify(v) end
print(table.concat(parts, " "))

local text = "the quick brown fox"
print((text:gsub("%w+", function(w) return w:sub(1, 1):upper() .. w:sub(2) end)), select(2, text:gsub("o", "0")))
for word, len in text:gmatch("(%w+)()") do io.write(word, ":", len, " ") end
print()

local list = {5, 3, 8, 1}
table.insert(list, 1, 9)
table.remove(list, 3)
table.sort(list, function(a, b) return a > b end)
print(table.concat(list, ","), #list, 10 / 4, 10 // 4, -7 // 2, -7 % 3, 3 == 3.0, math.type(3), math.type(3.0))

local n, acc = 0, {}
while n < 20 and (n % 7 ~= 6 or #acc < 2) do
  n = n + 1
  if n % 3 == 0 then acc[#acc + 1] = n end
end
repeat local stop = #acc > 0; table.remove(acc) until stop
print(n, #acc, next({}) == nil, type(nil), rawequal(acc, acc))
for i = 10, 1, -3 do io.write(i, " ") end
print()
