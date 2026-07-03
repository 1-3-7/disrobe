
local M = {}

M.simple_literals = {
    nil_value = nil,
    bool_true = true,
    bool_false = false,
    empty_string = "",
    short_string = "abc",
    long_string = [==[multi
line
literal]==],
    integer = 42,
    negative = -7,
    float = 3.14,
    big_float = 1e308,
    small_float = 1e-308,
    hex_int = 0x7FFFFFFF,
    hex_int_small = 0xCAFE,
}

local function add(a, b) return a + b end
local function sub(a, b) return a - b end
local function mul(a, b) return a * b end
local function div(a, b) return a / b end
local function mod(a, b) return a % b end
local function pow(a, b) return a ^ b end
local function neg(a)    return -a end
local function concat(a, b) return a .. b end
local function lt(a, b)  return a < b end
local function le(a, b)  return a <= b end
local function eq(a, b)  return a == b end
local function ne(a, b)  return a ~= b end
local function band_compat(a, b)
    local r, p = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then r = r + p end
        a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
    end
    return r
end

M.arith = { add = add, sub = sub, mul = mul, div = div, mod = mod, pow = pow,
            neg = neg, concat = concat, lt = lt, le = le, eq = eq, ne = ne,
            band_compat = band_compat }

local function control_flow(n)
    local out = {}
    if n < 0 then
        out[#out + 1] = "neg"
    elseif n == 0 then
        out[#out + 1] = "zero"
    else
        out[#out + 1] = "pos"
    end
    for i = 1, n do
        if i % 15 == 0 then
            out[#out + 1] = "fizzbuzz"
        elseif i % 3 == 0 then
            out[#out + 1] = "fizz"
        elseif i % 5 == 0 then
            out[#out + 1] = "buzz"
        else
            out[#out + 1] = tostring(i)
        end
    end
    local j = n
    while j > 0 do
        out[#out + 1] = "w" .. j
        j = j - 1
    end
    local k = 0
    repeat
        k = k + 1
        out[#out + 1] = "r" .. k
    until k >= 3
    return out
end

M.control_flow = control_flow

local function closures()
    local function make_counter(start, step)
        local v = start
        return function()
            v = v + step
            return v
        end
    end
    local function make_pair(a, b)
        local function get_a() return a end
        local function get_b() return b end
        local function swap()
            a, b = b, a
        end
        return get_a, get_b, swap
    end
    local function make_memo(f)
        local cache = {}
        return function(x)
            local hit = cache[x]
            if hit ~= nil then return hit end
            local v = f(x)
            cache[x] = v
            return v
        end
    end
    return make_counter, make_pair, make_memo
end

M.closures = closures

local function varargs(...)
    local n = select("#", ...)
    local first = select(1, ...)
    local packed = { ... }
    return n, first, packed
end

local function table_unpack_compat(t, i, j)
    if table.unpack then return table.unpack(t, i, j) end
    if unpack         then return unpack(t, i, j)       end
    return t[i]
end

M.varargs = varargs
M.table_unpack_compat = table_unpack_compat

local Vec = {}
Vec.__index = Vec
function Vec.new(x, y, z) return setmetatable({ x = x, y = y, z = z }, Vec) end
function Vec.__add(a, b)  return Vec.new(a.x + b.x, a.y + b.y, a.z + b.z) end
function Vec.__sub(a, b)  return Vec.new(a.x - b.x, a.y - b.y, a.z - b.z) end
function Vec.__mul(a, b)
    if type(b) == "number" then return Vec.new(a.x * b, a.y * b, a.z * b) end
    return a.x * b.x + a.y * b.y + a.z * b.z
end
function Vec.__unm(a)     return Vec.new(-a.x, -a.y, -a.z) end
function Vec.__eq(a, b)   return a.x == b.x and a.y == b.y and a.z == b.z end
function Vec.__lt(a, b)
    local an = a.x * a.x + a.y * a.y + a.z * a.z
    local bn = b.x * b.x + b.y * b.y + b.z * b.z
    return an < bn
end
function Vec.__le(a, b)
    local an = a.x * a.x + a.y * a.y + a.z * a.z
    local bn = b.x * b.x + b.y * b.y + b.z * b.z
    return an <= bn
end
function Vec.__tostring(v) return "Vec(" .. v.x .. "," .. v.y .. "," .. v.z .. ")" end
function Vec.__concat(a, b) return tostring(a) .. tostring(b) end
function Vec.__len(v)     return 3 end
function Vec.__index(t, k)
    if k == "magnitude" then
        return math.sqrt(t.x * t.x + t.y * t.y + t.z * t.z)
    end
    return rawget(Vec, k)
end
function Vec.__newindex(t, k, v) rawset(t, k, v) end
function Vec.__call(v, k) return ({ x = v.x, y = v.y, z = v.z })[k] end

M.Vec = Vec

local Proxy = {}
Proxy.__metatable = "locked"
Proxy.__index = function(t, k)
    local r = rawget(t, "_inner")
    return r and r[k] or nil
end
Proxy.__newindex = function(t, k, v)
    local r = rawget(t, "_inner")
    if r ~= nil then r[k] = v end
end
function Proxy.wrap(t) return setmetatable({ _inner = t }, Proxy) end

M.Proxy = Proxy

local function coroutine_demo()
    local function producer()
        for i = 1, 5 do coroutine.yield(i * 2) end
    end
    local co = coroutine.create(producer)
    local results = {}
    while true do
        local ok, v = coroutine.resume(co)
        if not ok or v == nil then break end
        results[#results + 1] = v
    end
    return results
end

local function coroutine_wrap_demo()
    local gen = coroutine.wrap(function()
        local i = 0
        while i < 4 do
            i = i + 1
            coroutine.yield(i, i * i)
        end
    end)
    local out = {}
    for _ = 1, 4 do
        local idx, sq = gen()
        out[#out + 1] = { idx, sq }
    end
    return out
end

M.coroutine_demo = coroutine_demo
M.coroutine_wrap_demo = coroutine_wrap_demo

local function pcall_demo()
    local ok, err = pcall(function() error("boom") end)
    local ok2, msg = xpcall(function() error({ code = 1, why = "fail" }) end,
        function(e)
            if type(e) == "table" then return e.code .. ":" .. e.why end
            return tostring(e)
        end)
    local ok3, val = pcall(function() return 7 end)
    return ok, err, ok2, msg, ok3, val
end

M.pcall_demo = pcall_demo

local function goto_demo(n)
    local loader = load or loadstring
    local src = [[
        local n = ...
        local r = {}
        for i = 1, n do
            if i % 2 == 0 then goto continue end
            r[#r + 1] = i
            ::continue::
        end
        do
            local k = 0
            ::loop::
            k = k + 1
            if k < 3 then goto loop end
            r[#r + 1] = "k=" .. k
        end
        return r
    ]]
    if not loader then return {} end
    local chunk, err = loader(src)
    if not chunk then return { err } end
    local ok, r = pcall(chunk, n)
    if ok then return r end
    return {}
end

M.goto_demo = goto_demo

local function string_lib_demo()
    local s = "Hello, World!"
    local lower = s:lower()
    local upper = s:upper()
    local len = #s
    local sub = s:sub(1, 5)
    local rev = s:reverse()
    local rep = s:rep(2, "-")
    local f1, f2 = s:find("World")
    local m = s:match("(%w+), (%w+)")
    local gm = {}
    for w in s:gmatch("%w+") do gm[#gm + 1] = w end
    local g = s:gsub("World", "Lua")
    local fmt = string.format("%d:%s:%.2f:%x", 7, "x", 3.14159, 255)
    local byte_a = string.byte("A")
    local char_a = string.char(65, 66, 67)
    return lower, upper, len, sub, rev, rep, f1, f2, m, gm, g, fmt, byte_a, char_a
end

M.string_lib_demo = string_lib_demo

local function table_lib_demo()
    local t = { 5, 3, 1, 4, 2 }
    table.sort(t)
    table.sort(t, function(a, b) return a > b end)
    table.insert(t, 99)
    table.insert(t, 1, 0)
    table.remove(t, 1)
    table.remove(t)
    local cc = table.concat({ "a", "b", "c" }, "-")
    return t, cc
end

M.table_lib_demo = table_lib_demo

local function math_lib_demo()
    local s = math.sqrt(2)
    local p = math.pi
    local h = math.huge
    local sm = -math.huge
    local r = math.random
    local rs = math.random(1, 10)
    local rb = math.random()
    local mx = math.max(1, 5, 3, 9, 2)
    local mn = math.min(1, 5, 3, 9, 2)
    local fl = math.floor(3.7)
    local ce = math.ceil(3.2)
    local ab = math.abs(-5)
    local mh = math.fmod(10, 3)
    local sn = math.sin(p / 2)
    local cs = math.cos(0)
    local tn = math.tan(p / 4)
    local ex = math.exp(1)
    local lg = math.log(math.exp(1))
    local pw = math.pow and math.pow(2, 10) or 2 ^ 10
    return s, p, h, sm, r, rs, rb, mx, mn, fl, ce, ab, mh, sn, cs, tn, ex, lg, pw
end

M.math_lib_demo = math_lib_demo

local function io_demo()
    local w = io.write
    local r = io.read
    local out = io.stdout
    local err = io.stderr
    return w, r, out, err
end

local function os_demo()
    local t = os.time()
    local cl = os.clock()
    local dt = os.date("%Y-%m-%d", t)
    local gt = os.getenv("PATH")
    local df = os.difftime(t, 0)
    return t, cl, dt, gt, df
end

M.io_demo = io_demo
M.os_demo = os_demo

local function ipairs_pairs_demo(t)
    local arr_acc = {}
    for i, v in ipairs(t) do arr_acc[#arr_acc + 1] = { i, v } end
    local map_acc = {}
    for k, v in pairs(t) do map_acc[#map_acc + 1] = { k, v } end
    return arr_acc, map_acc
end

M.ipairs_pairs_demo = ipairs_pairs_demo

local function setfenv_compat()
    if setfenv and getfenv then
        local f = function() return foo end
        local env = setmetatable({ foo = "hi" }, { __index = _G })
        setfenv(f, env)
        return f(), getfenv(f).foo
    end
    return nil, nil
end

M.setfenv_compat = setfenv_compat

local function require_demo()
    local ok_str, str = pcall(require, "string")
    local ok_tbl, tbl = pcall(require, "table")
    return ok_str, str, ok_tbl, tbl
end

M.require_demo = require_demo

local function rawops_demo(t, k, v)
    rawset(t, k, v)
    local got = rawget(t, k)
    local same = rawequal(t, t)
    local n = rawlen and rawlen(t) or #t
    return got, same, n
end

M.rawops_demo = rawops_demo

local long_table = {
    [1] = "alpha", [2] = "beta", [3] = "gamma", [4] = "delta",
    [5] = "epsilon", [6] = "zeta", [7] = "eta", [8] = "theta",
    [9] = "iota", [10] = "kappa", [11] = "lambda", [12] = "mu",
    [13] = "nu", [14] = "xi", [15] = "omicron", [16] = "pi",
    [17] = "rho", [18] = "sigma", [19] = "tau", [20] = "upsilon",
    [21] = "phi", [22] = "chi", [23] = "psi", [24] = "omega",
    a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8,
    nested = { { 1, 2, { 3, 4, { 5, 6, { 7, 8 } } } } },
}

M.long_table = long_table

local function deep_recursion(n)
    if n <= 0 then return 0 end
    return 1 + deep_recursion(n - 1)
end

local function mutual_a(n) if n <= 0 then return "a" end return mutual_a == nil and "" or "" .. (function() return n end)() end
local function pingpong(n, a, b)
    if n <= 0 then return a, b end
    return pingpong(n - 1, b, a + b)
end

M.deep_recursion = deep_recursion
M.pingpong = pingpong

local function long_expression()
    local a, b, c, d, e, f, g, h = 1, 2, 3, 4, 5, 6, 7, 8
    local r = ((a + b) * (c - d)) % ((e + f) * (g - h))
           + ((a * b * c * d) - (e * f * g * h))
           / (((a ^ 2) + (b ^ 2)) - ((c ^ 2) + (d ^ 2)) + 1)
           * (-((a - b) * (c - d) + (e - f) * (g - h)))
    local s = ("a" .. "b") .. ("c" .. "d") .. ("e" .. "f") .. ("g" .. "h") ..
              ("i" .. "j") .. ("k" .. "l") .. ("m" .. "n") .. ("o" .. "p")
    local cond = (a < b) and (b < c) and (c < d) and (d < e) and (e < f) and
                 (f < g) and (g < h) and not (h < a)
    return r, s, cond
end

M.long_expression = long_expression

local function logical_short_circuit(a, b, c)
    local x = a and b or c
    local y = not a and not b and c
    local z = (a or b) and (c or a)
    return x, y, z
end

M.logical_short_circuit = logical_short_circuit

local function string_packing_compat()
    if string.pack and string.unpack then
        local s = string.pack(">i4i4f", 1, 2, 3.5)
        local a, b, f, _ = string.unpack(">i4i4f", s)
        return a, b, f
    end
    return nil, nil, nil
end

local function utf8_lib_compat()
    local ok, lib = pcall(require, "utf8")
    if ok and lib and lib.char and lib.codepoint then
        local s = lib.char(72, 101, 108, 108, 111)
        local cp = lib.codepoint(s, 1)
        return s, cp
    end
    return nil, nil
end

M.string_packing_compat = string_packing_compat
M.utf8_lib_compat = utf8_lib_compat

local function bitops_compat()
    local v51 = load or loadstring
    local src = [[return function(a, b)
        return (a & b), (a | b), (a ~ b), (~a), (a << 2), (a >> 1)
    end]]
    local chunk = v51 and v51(src)
    if chunk then
        local ok, fn = pcall(chunk)
        if ok and type(fn) == "function" then
            local p1, p2 = pcall(fn, 0xF0, 0x0F)
            if p1 then return p2 end
        end
    end
    return nil
end

M.bitops_compat = bitops_compat

local function integer_div_compat()
    local v = load or loadstring
    local chunk = v and v("return 10 // 3, 10.0 // 3.0, 10 % 3")
    if chunk then
        local ok, a, b, c = pcall(chunk)
        if ok then return a, b, c end
    end
    return math.floor(10 / 3), math.floor(10.0 / 3.0), 10 % 3
end

M.integer_div_compat = integer_div_compat

local function integer_for_5_4()
    local v = load or loadstring
    local src = [[
        local out = {}
        for i = 1, 10, 2 do out[#out + 1] = i end
        for i = 10, 1, -2 do out[#out + 1] = i end
        return out
    ]]
    local chunk = v and v(src)
    if chunk then
        local ok, r = pcall(chunk)
        if ok then return r end
    end
    return {}
end

M.integer_for_5_4 = integer_for_5_4

local function to_be_closed_5_4()
    local v = load or loadstring
    local src = [[
        local function make()
            return setmetatable({}, { __close = function(_, _) end })
        end
        do
            local x <close> = make()
            return x ~= nil
        end
    ]]
    local chunk = v and v(src)
    if chunk then
        local ok, r = pcall(chunk)
        if ok then return r end
    end
    return false
end

M.to_be_closed_5_4 = to_be_closed_5_4

local function const_attrib_5_4()
    local v = load or loadstring
    local chunk = v and v([[local x <const> = 42 return x]])
    if chunk then
        local ok, r = pcall(chunk)
        if ok then return r end
    end
    return 42
end

M.const_attrib_5_4 = const_attrib_5_4

local function math_tointeger_compat()
    if math.tointeger then
        return math.tointeger(7.0), math.tointeger(7.5), math.tointeger("9")
    end
    local function ti(x)
        local n = tonumber(x)
        if type(n) == "number" and n == math.floor(n) then return math.floor(n) end
        return nil
    end
    return ti(7.0), ti(7.5), ti("9")
end

local function math_type_compat()
    if math.type then return math.type(1), math.type(1.0), math.type("x") end
    return "number", "number", nil
end

M.math_tointeger_compat = math_tointeger_compat
M.math_type_compat = math_type_compat

local function debug_lib_demo()
    local info = debug.getinfo and debug.getinfo(1, "Sl")
    local tb = debug.traceback and debug.traceback("trace", 1)
    return info, tb
end

M.debug_lib_demo = debug_lib_demo

local function load_string_compat(src)
    local loader = load or loadstring
    if not loader then return nil end
    local chunk, err = loader(src)
    if not chunk then return nil, err end
    return chunk
end

M.load_string_compat = load_string_compat

local function pack_unpack_demo()
    local pk = table.pack and table.pack(1, 2, 3, 4)
    if not pk then pk = { 1, 2, 3, 4, n = 4 } end
    local sum = 0
    for i = 1, pk.n do sum = sum + pk[i] end
    return sum
end

M.pack_unpack_demo = pack_unpack_demo

local function long_branch_chain(n)
    if     n == 1  then return "one"
    elseif n == 2  then return "two"
    elseif n == 3  then return "three"
    elseif n == 4  then return "four"
    elseif n == 5  then return "five"
    elseif n == 6  then return "six"
    elseif n == 7  then return "seven"
    elseif n == 8  then return "eight"
    elseif n == 9  then return "nine"
    elseif n == 10 then return "ten"
    elseif n == 11 then return "eleven"
    elseif n == 12 then return "twelve"
    elseif n == 13 then return "thirteen"
    elseif n == 14 then return "fourteen"
    elseif n == 15 then return "fifteen"
    elseif n == 16 then return "sixteen"
    elseif n == 17 then return "seventeen"
    elseif n == 18 then return "eighteen"
    elseif n == 19 then return "nineteen"
    elseif n == 20 then return "twenty"
    else                return "many"
    end
end

M.long_branch_chain = long_branch_chain

local function nested_loops(rows, cols)
    local grid = {}
    for r = 1, rows do
        grid[r] = {}
        for c = 1, cols do
            grid[r][c] = r * 100 + c
        end
    end
    local sum = 0
    for r = 1, rows do
        for c = 1, cols do
            sum = sum + grid[r][c]
        end
    end
    return sum
end

M.nested_loops = nested_loops

local function table_method_chain()
    local s = ("  hello  "):gsub("^%s+", ""):gsub("%s+$", ""):upper():rep(2, "/")
    return s
end

M.table_method_chain = table_method_chain

local Stack = {}
Stack.__index = Stack
function Stack.new() return setmetatable({ items = {}, n = 0 }, Stack) end
function Stack:push(v) self.n = self.n + 1; self.items[self.n] = v end
function Stack:pop()
    if self.n == 0 then return nil end
    local v = self.items[self.n]
    self.items[self.n] = nil
    self.n = self.n - 1
    return v
end
function Stack:peek() return self.items[self.n] end
function Stack:size() return self.n end

local Queue = setmetatable({}, { __index = Stack })
Queue.__index = Queue
function Queue.new() return setmetatable({ items = {}, head = 1, n = 0 }, Queue) end
function Queue:enqueue(v) self.n = self.n + 1; self.items[self.head + self.n - 1] = v end
function Queue:dequeue()
    if self.n == 0 then return nil end
    local v = self.items[self.head]
    self.items[self.head] = nil
    self.head = self.head + 1
    self.n = self.n - 1
    return v
end

M.Stack = Stack
M.Queue = Queue

local function exception_chain()
    local function step1() error("step1") end
    local function step2() step1() end
    local function step3() step2() end
    local ok, err = pcall(step3)
    return ok, err
end

local function safe_caller(fn, ...)
    local ok, r1, r2, r3 = pcall(fn, ...)
    return ok, r1, r2, r3
end

M.exception_chain = exception_chain
M.safe_caller = safe_caller

local function string_interp_compat()
    local name, count = "world", 42
    return string.format("hello, %s - count=%d", name, count)
end

M.string_interp_compat = string_interp_compat

local function table_with_holes()
    local t = { 1, 2, nil, 4, nil, 6 }
    local n = #t
    local sum = 0
    for i = 1, 6 do if t[i] then sum = sum + t[i] end end
    return n, sum
end

M.table_with_holes = table_with_holes

local function table_remove_during_iter()
    local t = { 10, 20, 30, 40, 50 }
    for i = #t, 1, -1 do
        if t[i] % 20 == 0 then table.remove(t, i) end
    end
    return t
end

M.table_remove_during_iter = table_remove_during_iter

local function method_call_styles(obj)
    local a = obj:size()
    local b = obj.size(obj)
    return a, b
end

M.method_call_styles = method_call_styles

local function chained_assignments()
    local a, b, c = 1, 2, 3
    a, b, c = c, a, b
    a, b, c = b, c, a
    a, b = a + b, a - b
    local arr = {}
    arr[1], arr[2], arr[3], arr[4] = a, b, c, a + b + c
    return arr
end

M.chained_assignments = chained_assignments

local function string_metatable_demo()
    local s = "lua"
    return s:upper(), s.upper(s), getmetatable("").__index == string
end

M.string_metatable_demo = string_metatable_demo

local function huge_concat()
    local parts = {}
    for i = 1, 32 do parts[i] = tostring(i) end
    return table.concat(parts, ",")
end

M.huge_concat = huge_concat

local function tail_calls(n, acc)
    acc = acc or 0
    if n <= 0 then return acc end
    return tail_calls(n - 1, acc + n)
end

M.tail_calls = tail_calls

local function multiple_returns()
    local function pair() return 1, 2 end
    local function triple() return 3, 4, 5 end
    local a, b = pair()
    local c, d, e = triple()
    local arr = { pair(), triple() }
    local arr2 = { triple(), pair() }
    return a, b, c, d, e, arr, arr2
end

M.multiple_returns = multiple_returns

local function table_constructor_styles()
    local list_only = { 10, 20, 30 }
    local hash_only = { a = 1, b = 2 }
    local mixed = { 1, 2, 3, name = "mixed", [99] = "ninetynine" }
    local nested = {
        { 1, 2, 3 },
        { 4, 5, 6 },
        meta = { rows = 2, cols = 3 },
    }
    local computed_keys = { [1 + 1] = "two", [2 * 2] = "four" }
    return list_only, hash_only, mixed, nested, computed_keys
end

M.table_constructor_styles = table_constructor_styles

local function string_byte_walk(s)
    local out = {}
    for i = 1, #s do out[i] = string.byte(s, i) end
    return out
end

M.string_byte_walk = string_byte_walk

local function format_kitchen_sink()
    return string.format(
        "%d|%i|%u|%o|%x|%X|%c|%s|%q|%e|%E|%f|%g|%G|%%",
        7, 7, 7, 0x1F, 255, 255, 0x41, "abc", "with\nnewlines", 1e6, 1e6,
        3.14, 1234567.89, 1234567.89)
end

M.format_kitchen_sink = format_kitchen_sink

local function bench_marker()
    local total = 0
    for i = 1, 100 do
        for j = 1, 10 do
            total = total + (i * j) - (i + j)
        end
    end
    return total
end

M.bench_marker = bench_marker

local function deep_clone(t, seen)
    seen = seen or {}
    if type(t) ~= "table" then return t end
    if seen[t] then return seen[t] end
    local out = {}
    seen[t] = out
    for k, v in pairs(t) do
        out[deep_clone(k, seen)] = deep_clone(v, seen)
    end
    return setmetatable(out, getmetatable(t))
end

local function shallow_eq(a, b)
    if type(a) ~= type(b) then return false end
    if type(a) ~= "table" then return a == b end
    for k, v in pairs(a) do if b[k] ~= v then return false end end
    for k, v in pairs(b) do if a[k] ~= v then return false end end
    return true
end

M.deep_clone = deep_clone
M.shallow_eq = shallow_eq

local function filter(arr, pred)
    local out = {}
    for _, v in ipairs(arr) do if pred(v) then out[#out + 1] = v end end
    return out
end

local function map(arr, f)
    local out = {}
    for i, v in ipairs(arr) do out[i] = f(v) end
    return out
end

local function reduce(arr, f, init)
    local acc = init
    for _, v in ipairs(arr) do acc = f(acc, v) end
    return acc
end

local function zip(a, b)
    local n = math.min(#a, #b)
    local out = {}
    for i = 1, n do out[i] = { a[i], b[i] } end
    return out
end

local function take(arr, n)
    local out = {}
    for i = 1, math.min(n, #arr) do out[i] = arr[i] end
    return out
end

local function drop(arr, n)
    local out = {}
    for i = n + 1, #arr do out[#out + 1] = arr[i] end
    return out
end

M.filter = filter
M.map = map
M.reduce = reduce
M.zip = zip
M.take = take
M.drop = drop

local function curry(f)
    return function(a) return function(b) return f(a, b) end end
end

local function compose(f, g)
    return function(x) return f(g(x)) end
end

local function partial(f, ...)
    local args = { ... }
    local n = select("#", ...)
    return function(...)
        local rest = { ... }
        local merged = {}
        for i = 1, n do merged[i] = args[i] end
        for i = 1, select("#", ...) do merged[n + i] = rest[i] end
        return f((function() return table_unpack_compat(merged, 1, #merged) end)())
    end
end

M.curry = curry
M.compose = compose
M.partial = partial

local function fib_iter(n)
    if n < 2 then return n end
    local a, b = 0, 1
    for _ = 2, n do
        a, b = b, a + b
    end
    return b
end

local function fact_iter(n)
    local p = 1
    for i = 2, n do p = p * i end
    return p
end

local function gcd(a, b)
    while b ~= 0 do
        a, b = b, a % b
    end
    return a
end

local function lcm(a, b) return (a * b) / gcd(a, b) end

local function is_prime(n)
    if n < 2 then return false end
    if n < 4 then return true end
    if n % 2 == 0 then return false end
    local i = 3
    while i * i <= n do
        if n % i == 0 then return false end
        i = i + 2
    end
    return true
end

M.fib_iter = fib_iter
M.fact_iter = fact_iter
M.gcd = gcd
M.lcm = lcm
M.is_prime = is_prime

local function quicksort(arr, lo, hi)
    lo = lo or 1
    hi = hi or #arr
    if lo < hi then
        local pivot = arr[hi]
        local idx = lo - 1
        for j = lo, hi - 1 do
            if arr[j] <= pivot then
                idx = idx + 1
                arr[idx], arr[j] = arr[j], arr[idx]
            end
        end
        arr[idx + 1], arr[hi] = arr[hi], arr[idx + 1]
        quicksort(arr, lo, idx)
        quicksort(arr, idx + 2, hi)
    end
    return arr
end

local function binary_search(arr, target)
    local lo, hi = 1, #arr
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        if arr[mid] == target then return mid end
        if arr[mid] < target then lo = mid + 1 else hi = mid - 1 end
    end
    return nil
end

M.quicksort = quicksort
M.binary_search = binary_search

local LinkedList = {}
LinkedList.__index = LinkedList
function LinkedList.new() return setmetatable({ head = nil, n = 0 }, LinkedList) end
function LinkedList:prepend(v) self.head = { val = v, next = self.head }; self.n = self.n + 1 end
function LinkedList:append(v)
    local node = { val = v, next = nil }
    if self.head == nil then self.head = node else
        local cur = self.head
        while cur.next do cur = cur.next end
        cur.next = node
    end
    self.n = self.n + 1
end
function LinkedList:to_array()
    local out = {}
    local cur = self.head
    while cur do
        out[#out + 1] = cur.val
        cur = cur.next
    end
    return out
end
function LinkedList:reverse()
    local prev, cur = nil, self.head
    while cur do
        cur.next, prev, cur = prev, cur, cur.next
    end
    self.head = prev
    return self
end

M.LinkedList = LinkedList

local Set = {}
Set.__index = Set
function Set.new(arr)
    local s = setmetatable({ members = {}, n = 0 }, Set)
    if arr then for _, v in ipairs(arr) do s:add(v) end end
    return s
end
function Set:add(v) if not self.members[v] then self.members[v] = true; self.n = self.n + 1 end end
function Set:remove(v) if self.members[v] then self.members[v] = nil; self.n = self.n - 1 end end
function Set:has(v) return self.members[v] == true end
function Set:union(other)
    local out = Set.new()
    for k in pairs(self.members) do out:add(k) end
    for k in pairs(other.members) do out:add(k) end
    return out
end
function Set:intersect(other)
    local out = Set.new()
    for k in pairs(self.members) do if other.members[k] then out:add(k) end end
    return out
end
function Set:diff(other)
    local out = Set.new()
    for k in pairs(self.members) do if not other.members[k] then out:add(k) end end
    return out
end

M.Set = Set

local function event_emitter()
    local listeners = {}
    local function on(event, fn)
        listeners[event] = listeners[event] or {}
        listeners[event][#listeners[event] + 1] = fn
    end
    local function emit(event, ...)
        local arr = listeners[event]
        if not arr then return 0 end
        for _, fn in ipairs(arr) do fn(...) end
        return #arr
    end
    local function off(event, fn)
        local arr = listeners[event]
        if not arr then return end
        for i = #arr, 1, -1 do if arr[i] == fn then table.remove(arr, i) end end
    end
    return { on = on, emit = emit, off = off }
end

M.event_emitter = event_emitter

local function state_machine(initial, transitions)
    local state = initial
    local function fire(event)
        local from = transitions[state]
        if not from then return false end
        local to = from[event]
        if not to then return false end
        state = to
        return true
    end
    local function current() return state end
    return { fire = fire, current = current }
end

M.state_machine = state_machine

local function lru_cache(capacity)
    local cache = {}
    local order = {}
    local n = 0
    local function touch(key)
        for i = 1, n do
            if order[i] == key then
                table.remove(order, i)
                order[n] = key
                return
            end
        end
    end
    local function get(key)
        if cache[key] == nil then return nil end
        touch(key)
        return cache[key]
    end
    local function set(key, value)
        if cache[key] ~= nil then
            cache[key] = value
            touch(key)
            return
        end
        if n >= capacity then
            local evict = order[1]
            cache[evict] = nil
            table.remove(order, 1)
            n = n - 1
        end
        cache[key] = value
        n = n + 1
        order[n] = key
    end
    return { get = get, set = set, size = function() return n end }
end

M.lru_cache = lru_cache

local function trampoline(f, ...)
    local result = f(...)
    while type(result) == "function" do
        result = result()
    end
    return result
end

M.trampoline = trampoline

local function generator_take(gen, n)
    local out = {}
    for i = 1, n do
        local v = gen()
        if v == nil then break end
        out[i] = v
    end
    return out
end

local function range_gen(start, stop, step)
    step = step or 1
    local i = start - step
    return function()
        i = i + step
        if (step > 0 and i > stop) or (step < 0 and i < stop) then return nil end
        return i
    end
end

M.generator_take = generator_take
M.range_gen = range_gen

local function string_builder()
    local parts, n = {}, 0
    local function append(s) n = n + 1; parts[n] = s end
    local function build(sep) return table.concat(parts, sep or "") end
    local function clear() parts, n = {}, 0 end
    local function size() return n end
    return { append = append, build = build, clear = clear, size = size }
end

M.string_builder = string_builder

local function smoke()
    local s1 = M.string_lib_demo()
    local s2 = M.table_lib_demo()
    local s3 = M.math_lib_demo()
    local s4 = M.control_flow(5)
    local s5 = M.coroutine_demo()
    local s6 = M.coroutine_wrap_demo()
    local s7 = M.pcall_demo()
    local s8 = M.goto_demo(5)
    local s9 = M.exception_chain()
    local sA = M.long_expression()
    local sB = M.bench_marker()
    return s1, s2, s3, s4, s5, s6, s7, s8, s9, sA, sB
end

M.smoke = smoke

print("edge_cases loaded")

return M
