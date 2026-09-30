a, e = 5, 0
local b = 5
d = (a ~= b or e == 7) and b or 7
print(d)
e = 7
d = (a ~= b or e == 7) and b or 7
print(d)
a = 4
d = (a ~= b or e == 7) and b or 7
print(d)

local cfg = { lo = 1, hi = 9 }
local function clamp(v)
  local r = (cfg.lo > v or cfg.hi < v) and cfg.lo or v
  return r
end
print(clamp(0), clamp(5), clamp(12))
