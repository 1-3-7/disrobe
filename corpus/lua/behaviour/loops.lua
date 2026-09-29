local state = "idle"
local transitions = {idle = {go = "running"}, running = {stop = "idle", pause = "paused"}, paused = {go = "running"}}
local log = {}
for _, event in ipairs({"go", "pause", "go", "stop", "stop"}) do
  local nxt = transitions[state][event]
  if nxt then
    state = nxt
    log[#log + 1] = event .. ">" .. state
  else
    log[#log + 1] = event .. "!"
  end
end
print(table.concat(log, " "), state)

for _, v in ipairs({1, 2, 3}) do
  if v == 2 then break end
  print("ipairs", v)
end

for i = 1, 3 do
  if i == 2 then break end
  print("numeric", i)
end

local found
for k, v in pairs({a = 1}) do
  if v > 0 then
    found = k
  end
end
print(found)

local total = 0
for _, row in ipairs({{1, 2}, {3, 4}, {5}}) do
  for _, cell in ipairs(row) do
    if cell == 4 then break end
    total = total + cell
  end
end
print(total)

local function memo(f)
  local cache = {}
  return function(n)
    local hit = cache[n]
    if hit == nil then
      hit = f(n)
      cache[n] = hit
    end
    return hit
  end
end
local calls = 0
local square = memo(function(n) calls = calls + 1 return n * n end)
print(square(4), square(4), square(5), calls)

local function curry(f, a) return function(...) return f(a, ...) end end
local add3 = curry(function(x, y, z) return x + y + (z or 0) end, 1)
print(add3(2), add3(2, 3))

local words = {}
for w in ("The rain in Spain"):gmatch("%a+") do
  if #w > 3 then words[#words + 1] = w:lower() elseif w == "in" then words[#words + 1] = "IN" end
end
print(table.concat(words, " "))

local function first_even(list)
  for idx, v in ipairs(list) do
    if v % 2 == 0 then return idx, v end
  end
  return nil
end
print(first_even({1, 3, 6, 8}))
print(first_even({1, 3}))

local ok, count, second = pcall(function(...) return select("#", ...), ... end, "p", nil, "q")
print(ok, count, second)

local function two() return 1, 2 end
local one = two()
print(one)
print((two()))
print(ok, (("a,b"):gsub(",", ";")))

local reps = 0
repeat
  local doubled = reps * 2
  reps = reps + 1
until doubled >= 6
print(reps)

local sel = 5
local label = sel > 3 and (sel > 4 and "big" or "mid") or "small"
local neg = not (sel == 5) or sel
print(label, neg)
local function grade(v) return v > 3 and (v > 4 and "big" or "mid") or "small" end
print(grade(5), grade(4), grade(1))
local function pick(flag, a, b) return flag and a or b end
print(pick(true, false, "b"), pick(nil, 1, 2))

local fns = {}
for i = 1, 3 do
  local k = i * 10
  fns[i] = function(v) return v + k + i end
end
print(fns[1](1), fns[2](1), fns[3](1))

local function account(balance)
  local function deposit(v) balance = balance + v return balance end
  local function withdraw(v)
    if v > balance then return nil, "insufficient" end
    balance = balance - v
    return balance
  end
  return deposit, withdraw
end
local dep, wd = account(10)
print(dep(5), wd(3), wd(100))

local hit = nil
for _, row in ipairs({{1, 2}, {3, 4}}) do
  for _, v in ipairs(row) do
    if v == 3 then hit = v break end
  end
  if hit then break end
end
print(hit)

local shout = setmetatable({}, {__index = function(_, key) return key .. "!" end})
print(shout.hello, rawget(shout, "hello"))

local acc, step = 0, 10
while true do
  step = step - 3
  if step < 0 then break end
  acc = acc + step
end
print(acc, step)

g_counter = 1
local before = g_counter
g_counter = g_counter + 1
print(before, g_counter)

local shared = 1
local function scale_shared()
  local old = shared
  shared = shared * 10
  return old, shared
end
print(scale_shared())

local base = 3
local tripled = base * 3
base = 0
print(tripled, base)
