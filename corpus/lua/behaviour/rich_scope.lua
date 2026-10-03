local out = {}
local function emit(v) out[#out + 1] = tostring(v) end

local function after_generic_for(flag, a, b, c)
  local hits = {}
  if flag and a > 0 then
    if b < 18 and a > 4 then
      for _, v in ipairs({a, b, c % 6}) do
        hits[#hits + 1] = v
      end
    end
  elseif (a + a) >= c then
    hits[#hits + 1] = "else"
  end
  return table.concat(hits, ",")
end
emit(after_generic_for(true, 6, 3, 8))
emit(after_generic_for(true, 2, 3, 8))
emit(after_generic_for(false, 6, 3, 8))

do
  local a = 8
  local c = 6
  local d = 4
  local e = 8
  local n2 = 0
  repeat
    n2 = n2 + 1
    if e ~= (c - a) then
      local arr6 = {a, c, d, e}
      e = (arr6[1] * 2 + arr6[4]) % 1000
      local co7 = coroutine.wrap(function() coroutine.yield((11 * a) % 97) coroutine.yield(e) end)
      e = (co7() + co7()) % 1000
    end
  until n2 >= 4 or e == (7 - d)
  emit(a) emit(c) emit(d) emit(e)
end

do
  local a = 8
  local b = 6
  local c = 6
  local d = 4
  local e = 8
  emit(string.format("%03d", b % 1000) .. ("x"):rep(2))
  local n2 = 0
  repeat
    n2 = n2 + 1
    local function mr3(x) return x, x + 1 end
    local p3, q3 = mr3(e)
    b = (p3 * q3) % 1000
    if e ~= (c - a) then
      if (c - b) < b then
        local co5 = coroutine.wrap(function() coroutine.yield((3 % 2)) coroutine.yield(b) end)
        emit(co5() + co5())
      end
    end
  until n2 >= 4 or e == (7 - d)
  emit(a) emit(b) emit(c) emit(d) emit(e)
end

local function captured_after_loop(a, c, d)
  local b = 1
  if (10 <= (c * c) % 97) and d > 2 then
    for i2 = 1, 3 do
      b = (d + i2) % 1000
      local function va3(...) local s = 0 for i = 1, select('#', ...) do s = s + select(i, ...) end return s % 1000 end
      c = va3(a, b, a)
    end
    local n4 = 0
    repeat
      n4 = n4 + 1
      local ok5, v5 = pcall(function() if 10 == (0 % 2) then error("e") end return (b - 13) end)
      emit(ok5) emit(v5)
    until n4 >= 2 or not (a ~= c)
  end
  return b
end
emit(captured_after_loop(8, 7, 8))

local function break_after_threaded_then(a, s)
  local b, c, d = 4, 6, 6
  if ((a + d) > (b * c) % 97) and a > 6 then
    if #s > 40 then s = s:sub(-20) end
  else
    for i17 = 0, 1 do
      a = (d + i17) % 1000
      if ((b * b) % 97 ~= b) or b == 2 then break end
    end
  end
  return a, s
end
emit(break_after_threaded_then(9, "short"))
emit(break_after_threaded_then(30, string.rep("y", 45)))

print(table.concat(out, " "))
