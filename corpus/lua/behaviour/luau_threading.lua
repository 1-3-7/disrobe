local out = {}
local function emit(v) out[#out + 1] = tostring(v) end

do
  local b, c, d, e = 4, 3, 5, 4
  local n1 = 0
  while n1 < 5 and (not (e > (c * c) % 97) or n1 == 0) do
    n1 = n1 + 1
    local n2 = 0
    while n2 < 5 and ((4 ~= (7 % 6)) and b > 7 or n2 == 0) do
      n2 = n2 + 1
      emit(b + d)
    end
    if b ~= (4 - e) then break end
  end
  emit(n1)
end

do
  local c, d, e = 6, 2, 9
  local n4 = 0
  while n4 < 1 and ((c ~= e) or e == 9 or n4 == 0) do
    n4 = n4 + 1
    for i5 = 2, 5 do
      c = (e + i5) % 1000
      emit(c)
    end
    if not ((10 * 1) % 97 <= (19 % 2)) then break end
  end
  emit(c + d)
end

do
  local a, b, c = 3, 7, 5
  local n1 = 0
  repeat
    n1 = n1 + 1
    emit(c)
    if (8 + c) < (19 * 19) % 97 then break end
  until n1 >= 2 or (b + a) > 13
  emit(n1)
end

do
  local a, b, c, d = 4, 0, 2, 2
  if ((a + 13) ~= b) or d == 2 then
    a = a * 3
    emit(a)
  else
    emit(c)
  end
  emit(a + c)
end

do
  local t = {}
  local a, b, c, d, e = 6, 0, 9, 7, 5
  local rounds = 0
  repeat
    rounds = rounds + 1
    if (b - b) > (10 - 2) then
      emit("never")
    elseif ((e % 2) <= d) and a > 2 then
      if ((16 % 6) == (11 + e)) and e > 2 then
        e = (t[0] or (d + c))
        b = e % 1000
      elseif ((10 * b) % 97 < (4 * a) % 97) and d > 4 then
        t[0] = (e * c) % 97
      end
    end
    for i2 = 3, 6 do
      d = (d + i2) % 1000
    end
  until rounds >= 2
  emit(t[0]) emit(b) emit(d) emit(e)
end

do
  local b, c, d, e = 7, 1, 3, 5
  for i1 = 3, 4 do
    d = (c + i1) % 1000
    if (b + d) <= b then
      if not ((7 + e) == (c % 8)) then
        d = (not ((e + 0) ~= b)) and (b * b) % 97 or 2
      end
    else
      if (12 + 15) < d then
        emit("big")
      end
      emit(d)
    end
  end
end

do
  local t = {}
  local a, b, c, d, e = 9, 4, 9, 2, 8
  local n8 = 0
  while n8 < 2 and (((11 + 3) == d) or a == 4 or n8 == 0) do
    n8 = n8 + 1
    emit((t[3] or 10))
    if (e == (c % 10)) or e == 6 then
      emit("six")
    elseif ((d + c) >= (d % 7)) and d > 7 then
      emit(((c * c) % 97 * (8 - c)) % 97 % 1000)
    else
      a = (15 % 3) % 1000
    end
  end
  for i12 = 3, 7 do
    local n18 = 0
    repeat
      b = (a * 10) % 97 % 1000
    until n18 >= 2 or not ((b + b) >= 5)
    if 8 >= (b % 9) then
      d = (t[3] or (d % 3))
    end
  end
  emit(a) emit(b) emit(d)
end

local function after_branch(t, flag, a, d)
  local b = t[1]
  if flag then
    b = t[2] or (a + d)
  end
  b = (d > 1) and (a * 18) % 97 or (a + (b or 0))
  return b
end
emit(after_branch({}, true, 1, 2))
emit(after_branch({5}, false, 1, 0))
emit(after_branch({}, false, 4, 1))

local function guarded(a, b, c)
  local function id(x) return x end
  local both = (a or id(b)) and c
  return both
end
emit(guarded(1, 2, 3))
emit(guarded(nil, 2, 3))
emit(guarded(nil, nil, 3))
emit(guarded(false, false, 3))

local wide = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}
local sum = 0
for _, v in ipairs(wide) do sum = sum + v end
emit(#wide) emit(sum)
for _, event in ipairs({"go", "pause", "stop"}) do emit(event) end

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
local square = memo(function(n) return n * n end)
emit(square(7)) emit(square(7))

do
  local a = 4
  if (a >= (14 + a)) or c == 8 then
    a = f(c)
  end
end

do
  local t = {}
  local a = 2
  local c = 3
  local d = 9
  if ((a + 13) ~= b) or d == 2 then
    e = (t[0] or (c * d) % 97)
  else
    emit(((e % 7) + (e - e)) % 1000)
  end
end

local function explicit_nils()
  local t = {}
  local a = 8
  local c = 6
  local d = 2
  local e = 3
  if not (7 > (c + 2)) then
    b = (t[2] or (11 + d))
    for i1 = 3, 4 do
      emit((((7 + b) >= (10 + c)) and b > 9) and (19 % 9) or (b % 10))
    end
  end
  if (b - e) < e then
  else
    if e > b then
      repeat
        emit(f((d % 4)))
      until n4 >= 4 or c ~= (a - 14)
    else
      for i5 = 3, 4 do
        c = (d + i5) % 1000
        if not ((a * c) % 97 == (b % 8)) then break end
      end
    end
  end
  emit(a) emit(b) emit(c) emit(d) emit(e)
end
explicit_nils()

print(table.concat(out, " "))
