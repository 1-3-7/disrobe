local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
local t = {}
for i = 1, 10 do t[#t + 1] = fib(i) end
print(table.concat(t, ","))
local counts = {}
for _, w in ipairs({"a", "b", "a", "c", "b", "a"}) do counts[w] = (counts[w] or 0) + 1 end
local keys = {}
for k in pairs(counts) do keys[#keys + 1] = k end
table.sort(keys)
for _, k in ipairs(keys) do io.write(k, "=", counts[k], " ") end
print()
local function counter()
  local c = 0
  return function(step) c = c + (step or 1) return c end
end
local inc = counter()
inc() inc(5)
print(inc(), select("#", 1, nil, 3), select(2, "x", "y", "z"))
local s = "Hello World"
print(s:upper(), s:sub(1, 5), #s, s:rep(2, "-"), s:find("World"), string.format("%5.2f|%d|%s", math.pi, 42, true))
local ok, err = pcall(function() error({code = 7}) end)
print(ok, type(err), err.code)
local i = 0
repeat i = i + 3 until i > 10
while true do i = i - 1 if i % 4 == 0 then break end end
print(i, 7 // 2, 7 % 3, 2 ^ 10, 5 & 3, 5 | 3, 5 ~ 3, ~0, 1 << 4, 256 >> 4)
local mt = {__add = function(a, b) return setmetatable({v = a.v + b.v}, getmetatable(a)) end,
            __tostring = function(a) return "V(" .. a.v .. ")" end, __index = function(_, k) return k .. "!" end}
local a = setmetatable({v = 1}, mt)
local b = setmetatable({v = 2}, mt)
print(tostring(a + b), a.missing, rawget(a, "missing"))
goto skip
print("not printed")
::skip::
local co = coroutine.wrap(function(x) local y = coroutine.yield(x * 2) return y + 1 end)
print(co(5), co(10))
local packed = table.pack(1, 2, nil, 4)
print(packed.n, table.unpack({1, 2, 3}, 2))
