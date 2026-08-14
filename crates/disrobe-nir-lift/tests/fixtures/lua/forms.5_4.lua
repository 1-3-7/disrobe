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

local function constants(a)
  local added = a + 1.5
  local subtracted = a - 2.5
  local multiplied = a * 3.5
  local divided = a / 4.5
  local remainder = a % 5.5
  local floored = a // 6.5
  local raised = a ^ 7.5
  local immediate = a + 3
  local lowered = a - 4
  return added, subtracted, multiplied, divided, remainder, floored, raised,
    immediate, lowered
end

local function bitwise(a, b)
  local conjunction = a & b
  local disjunction = a | b
  local exclusive = a ~ b
  local complement = ~a
  local left = a << b
  local right = a >> b
  local leftfixed = a << 3
  local rightfixed = a >> 2
  local floored = a // b
  local flooredfixed = a // 4
  local maskedhigh = a & 0xF0F0F0F0F0F0
  local mergedhigh = b | 0xABCDEF012345
  local flippedhigh = a ~ 0x123456789ABC
  local fromconstant = 1 << a
  local towardconstant = 4096 >> b
  return conjunction, disjunction, exclusive, complement, left, right,
    leftfixed, rightfixed, floored, flooredfixed, maskedhigh, mergedhigh,
    flippedhigh, fromconstant, towardconstant
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

local function jumps(limit)
  local total = 0
  ::again::
  total = total + 1
  if total < limit then
    goto again
  end
  return total
end

local function scoped()
  local frozen <const> = 11
  local handle <close> = setmetatable({}, {
    __close = function()
      Counter = Counter - 1
    end,
  })
  Registry.total = Registry.total + frozen
  return handle ~= nil
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
  local k = constants(a)
  local y = bitwise(a // 1, b // 1)
  local z = logic(a, b)
  local c = closures()
  local w = tables({ a, b, tag = "seed" })
  local v = varargs(a, b, x)
  local u = loops(4)
  local j = jumps(3)
  local s = scoped()
  return x, k, y, z, c, w, v, u, j, s, selfcall(Registry)
end

return M
