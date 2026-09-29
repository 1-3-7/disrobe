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
