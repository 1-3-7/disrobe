do
  local t = {}
  local b, d = 0, 7
  local e = tonumber("5")
  local c = tonumber("1")
  if c > 0 then
    if e == 4 then
      local tmp = t[0] or 3
      e = tmp
      b = e % 1000
    else
      print(e * 9)
    end
  end
  print(b, d)
end

local function global_fallback(t, flag, a, d)
  if flag then
    shared = t[2] or (a + d)
  end
  shared = (d > 1) and (a * 18) % 97 or (a + (shared or 0))
end
global_fallback({}, true, 1, 2)
print(shared)
global_fallback({}, false, 1, 0)
print(shared)

local function selected_then_branch(t, e, c)
  local b, d = 0, 7
  if c > 0 then
    if e == 4 then
      local tmp = t[0] or 3
      e = tmp
      b = e % 1000
    else
      print("else", e * 9)
    end
  end
  print(b, d)
end
selected_then_branch({}, tonumber("5"), tonumber("1"))
selected_then_branch({}, tonumber("4"), tonumber("1"))

local function loop_body_local(c, e)
  local b = 7
  local log = {}
  local d = 3
  log[#log + 1] = (d % 7) + 1
  for i1 = 3, 4 do
    d = (c + i1) % 1000
    if (b + d) <= b then
      if not ((7 + e) == (c % 8)) then
        d = (not ((e + 0) ~= b)) and (b * b) % 97 or 2
      end
    else
      if (12 + 15) < d then
        log[#log + 1] = "big"
      end
      log[#log + 1] = d
    end
  end
  print(table.concat(log, " "))
end
loop_body_local(1, 5)
loop_body_local(-4, 7)

local function id(x) return x end
local function guarded(a, b, c)
  local both = (a or id(b)) and c
  return both
end
print(guarded(1, 2, 3), guarded(nil, 2, 3), guarded(nil, nil, 3), guarded(false, false, 3))

local function nested_fallback(t, flag, a, d)
  local b = t[1]
  if flag then
    b = t[2] or (a + d)
  end
  b = (d > 1) and (a * 18) % 97 or (a + (b or 0))
  return b
end
print(nested_fallback({}, true, 1, 2), nested_fallback({5}, false, 1, 0), nested_fallback({}, false, 4, 1))

local function called(x)
  print("called", x)
  return 1
end
local function dead_store_at_end()
  local a = 4
  limit = 8
  if (a >= (14 + a)) or limit == 8 then
    a = called(limit)
  end
end
dead_store_at_end()
