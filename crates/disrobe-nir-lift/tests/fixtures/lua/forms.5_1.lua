local M = {}

Counter = 0
Registry = { total = 0, tag = "seed" }

local function arithmetic(a, b)
  local sum = a + b
  local diff = a - b
  local prod = a * b
  local quot = a / b
  local rem = a % b
  local power = a ^ b
  local negated = -a
  local size = #Registry
  local joined = "v" .. a .. b
  return sum, diff, prod, quot, rem, power, negated, size, joined
end

local function logic(a, b)
  local inverted = not a
  local doubled = not not b
  local both = a and b
  local either = a or b
  local equal = a == b
  local less = a < b
  local lesseq = a <= b
  return inverted, doubled, both, either, equal, less, lesseq
end

local function closures()
  local made = {}
  for index = 1, 4 do
    local captured = index * 2
    made[index] = function()
      captured = captured + 1
      return captured
    end
    if index == 3 then
      break
    end
  end
  return made
end

local function tables(source)
  local copy = { source[1], source[2], n = 2 }
  copy.tag = "copy"
  copy[3] = source.tag
  for key, value in pairs(source) do
    copy[key] = value
  end
  for index = 1, #source do
    copy[index] = source[index]
  end
  return copy
end

local function selfcall(object)
  return object.total, Registry.tag
end

local function varargs(...)
  local packed = { ... }
  local first = ...
  return first, packed, select("#", ...)
end

local function loops(limit)
  local total = 0
  local step = 0
  while step < limit do
    step = step + 1
    total = total + step
  end
  repeat
    total = total - 1
  until total <= 0
  for index = limit, 1, -1 do
    total = total + index
  end
  return total
end

function M.entry(a, b)
  Counter = Counter + 1
  Registry.total = Counter
  local x = arithmetic(a, b)
  local y = logic(a, b)
  local z = closures()
  local w = tables({ a, b, tag = "seed" })
  local v = varargs(a, b, x)
  local u = loops(4)
  return x, y, z, w, v, u, selfcall(Registry)
end

return M
