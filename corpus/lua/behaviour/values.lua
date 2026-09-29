local function pick(a, b, c)
  local first = a or b
  local both = a and b
  local chain = a and b or c
  local guarded = (a or b) and c
  local nested = a or (b and c) or "none"
  return first, both, chain, guarded, nested
end
print(pick(nil, 2, 3))
print(pick(false, nil, 3))
print(pick(1, false, "c"))
print(pick(nil, nil, nil))

local function defaulted(t, key, fallback)
  local v = t[key] or fallback
  t[key] = v
  return v, t[key] ~= nil and "set" or "unset"
end
local cache = {a = 1}
print(defaulted(cache, "a", 9), defaulted(cache, "b", 7), defaulted(cache, "c", nil))

local function flags(n)
  local even = n % 2 == 0
  local big = n > 10
  local both = even and big
  local either = even or big
  local neither = not (even or big)
  return even, big, both, either, neither
end
print(flags(4))
print(flags(13))
print(flags(12))
print(flags(3))

local function clamp(v, lo, hi)
  v = v < lo and lo or v
  v = v > hi and hi or v
  return v
end
print(clamp(-5, 0, 10), clamp(5, 0, 10), clamp(50, 0, 10))

local function first_truthy(...)
  local a, b, c = ...
  local r = a or b or c
  return r
end
print(first_truthy(nil, false, "x"), first_truthy(0, 1, 2), first_truthy(nil, nil, nil))

local count = 0
local function tick(v)
  count = count + 1
  return v
end
local lazy = tick(false) and tick(true) or tick("fallback")
print(lazy, count)
count = 0
local lazy2 = tick(nil) or tick(false) or tick(0)
print(lazy2, count)

local t = {}
t.x = t.x or {}
t.x.n = (t.x.n or 0) + 1
t.x.n = (t.x.n or 0) + 1
print(t.x.n)

local s = nil
local len = s and #s or 0
local name = s or "anon"
print(len, name, s == nil and "nil" or "set")

local function sign(n)
  return n > 0 and 1 or n < 0 and -1 or 0
end
print(sign(5), sign(-5), sign(0))

local a, b = 3, nil
local swapped = b or a
local keep = a and b
print(swapped, keep, not a, not b, not not b)

i = "global i"
k, v = "global k", "global v"
for n = 1, 2 do
  print(n, i)
end
for key, val in pairs({x = 1}) do
  print(key, val, k, v)
end
for _, w in ipairs({"a"}) do
  local reader = function() return i .. w end
  print(reader())
end
