local function pick_constant(d, e, b, a)
  local c = 2
  c = ((d < d) or e == 0) and 17 or (b - a)
  local k = (d > 1) and 5 or (a + b)
  return c, k
end
print(pick_constant(4, 5, 0, 6))
print(pick_constant(4, 0, 0, 6))
print(pick_constant(0, 3, 2, 1))

local function pick_computed(a, b, d)
  b = (d > 1) and (b * 18) % 97 or (a + b)
  local both = ((d == 0) and (6 < d)) and (19 - d) or (a - d)
  return b, both
end
print(pick_computed(3, 4, 2))
print(pick_computed(3, 4, 0))
print(pick_computed(-1, 9, 7))

local function after_branch(t, flag, a, d)
  local b
  if flag then
    t[2] = a + d
  else
    b = t[2] or (a + d)
  end
  b = (d > 1) and (a * 18) % 97 or (a + (b or 0))
  return b, t[2]
end
print(after_branch({}, true, 3, 4))
print(after_branch({}, false, 3, 4))
print(after_branch({[2] = 8}, false, 3, 0))

local function guarded_loop(p, a, b)
  local total = 0
  if p then
    local n = 0
    while n < 3 and ((a < b) or n == 0) do
      n = n + 1
      a = a + 1
      total = total + n
    end
  else
    total = -1
  end
  return total, a
end
print(guarded_loop(true, 1, 2))
print(guarded_loop(true, 5, 2))
print(guarded_loop(false, 1, 2))

local function nested_guards(rows)
  local out = {}
  for i = 1, #rows do
    local r = rows[i]
    if r > 0 then
      local m = 0
      while m < r and ((m % 2 == 0) or m == 1) do
        m = m + 1
      end
      out[#out + 1] = m
    else
      out[#out + 1] = (r == 0) and 0 or -r
    end
  end
  return table.concat(out, ",")
end
print(nested_guards({3, 0, -4, 1, 6}))
