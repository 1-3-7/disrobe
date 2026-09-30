local function pick(first, ...args)
  return first, args[1], args[3], args.n
end
print(pick(1, 4, 5, 6, 7))
print(pick(2))

local function count(...t)
  t[1] = "first"
  local total = 0
  for i = 1, t.n do
    local v = t[i]
    total = total + (type(v) == "number" and v or 100)
  end
  return #t, t.n, total, ...
end
print(count(1, 2, 3))

local function outer(...rest)
  return function(extra)
    return rest.n + extra, rest[2]
  end
end
print(outer("a", "b")(10))

local function forward(...)
  local n = select("#", ...)
  return n, ...
end
print(forward(nil, false, 3))

global *
global counter = 5
global function bump(n)
  counter = counter + n
  return counter
end
print(bump(2), counter)
local ok, err = pcall(function()
  global counter = 1
end)
print(ok, (string.match(tostring(err), "global '%w+' already defined")))
local fine, message = pcall(function()
  global fresh = 3
  return fresh
end)
print(fine, message, fresh)

local acc = {}
for i = 10, 1, -3 do
  acc[#acc + 1] = i
end
for i = 1.5, 3 do
  acc[#acc + 1] = i
end
for k, v in pairs({ only = 1 }) do
  acc[#acc + 1] = k .. v
end
for i, v in ipairs({ 7, 8, 9 }) do
  if v == 8 then
    goto continue
  end
  acc[#acc + 1] = i * v
  ::continue::
end
for a, b, c in function(_, i)
  if i < 3 then
    return i + 1, i * 2, i * 3
  end
end, nil, 0 do
  acc[#acc + 1] = a + b + c
end
print(table.concat(acc, ","))

local x = 5
print(1 << x, x << 2, x >> 1, 256 >> x, -1 >> 60, 3 << -1)

local big = {}
for i = 1, 3000 do
  big[i] = i
end
local literal = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, n = "tail" }
print(#big, big[3000], #literal, literal[55], literal.n)

local function closes()
  local log = {}
  local function run()
    local guard <close> = setmetatable({}, { __close = function()
      log[#log + 1] = "closed"
    end })
    log[#log + 1] = "body"
  end
  run()
  for i = 1, 3 do
    local mark <close> = setmetatable({}, { __close = function()
      log[#log + 1] = "left" .. i
    end })
    if i == 2 then
      break
    end
  end
  return table.concat(log, " ")
end
print(closes())
