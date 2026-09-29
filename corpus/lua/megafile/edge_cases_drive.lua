local path = assert(arg and arg[1], "usage: lua edge_cases_drive.lua <program.lua>")
local handle = assert(io.open(path, "rb"))
local source = handle:read("*a")
handle:close()
local compile = loadstring or load
local program = assert(compile(source, "=megafile"))
local M = program()

local function norm(s)
    s = s:gsub("megafile:%d+:", "megafile:?:")
    s = s:gsub("to '[^']*'", "to '?'")
    s = s:gsub("local '[^']*'", "local '?'")
    return (s:gsub("upvalue '[^']*'", "upvalue '?'"))
end

local function key_order(a, b)
    if a.rank ~= b.rank then return a.rank < b.rank end
    if a.rank == 1 then return a.key < b.key end
    return a.text < b.text
end

local rank_of = { number = 1, string = 2, boolean = 3, table = 4 }

local function ser(v, seen, depth)
    local t = type(v)
    if t == "string" then return string.format("%q", norm(v)) end
    if t == "number" or t == "boolean" or t == "nil" then return tostring(v) end
    if t ~= "table" then return "<" .. t .. ">" end
    if seen[v] then return "<cycle>" end
    if depth > 8 then return "<deep>" end
    seen[v] = true
    local entries = {}
    for k, value in next, v do
        entries[#entries + 1] = {
            key = k,
            rank = rank_of[type(k)] or 5,
            text = ser(k, seen, depth + 1),
            value = value,
        }
    end
    table.sort(entries, key_order)
    local parts = {}
    for i = 1, #entries do
        local e = entries[i]
        parts[i] = "[" .. e.text .. "]=" .. ser(e.value, seen, depth + 1)
    end
    seen[v] = nil
    local mt = getmetatable(v)
    local tag = mt ~= nil and ("<mt:" .. type(mt) .. ">") or ""
    return tag .. "{" .. table.concat(parts, ",") .. "}"
end

local function show(name, ...)
    local n = select("#", ...)
    local parts = {}
    local values = { ... }
    for i = 1, n do parts[i] = ser(values[i], {}, 0) end
    print(name .. " #" .. n .. " " .. table.concat(parts, " "))
end

local function check(name, f, ...)
    show(name, pcall(f, ...))
end

local function types(...)
    local n = select("#", ...)
    local values = { ... }
    local out = {}
    for i = 1, n do out[i] = type(values[i]) end
    return table.concat(out, ",")
end

show("simple_literals", M.simple_literals)
local a = M.arith
for _, op in ipairs({ "add", "sub", "mul", "div", "mod", "pow", "lt", "le", "eq", "ne" }) do
    check("arith." .. op, a[op], 7, 3)
end
check("arith.neg", a.neg, 7)
check("arith.concat", a.concat, "a", 3)
check("arith.band_compat", a.band_compat, 12, 10)
for _, n in ipairs({ -1, 0, 15 }) do check("control_flow" .. n, M.control_flow, n) end

check("closures", function()
    local make_counter, make_pair, make_memo = M.closures()
    local counter = make_counter(10, 3)
    local c1, c2, c3 = counter(), counter(), counter()
    local get_a, get_b, swap = make_pair(1, 2)
    local before = { get_a(), get_b() }
    swap()
    local after = { get_a(), get_b() }
    local calls = 0
    local memo = make_memo(function(x) calls = calls + 1 return x * x end)
    return c1, c2, c3, before, after, memo(4), memo(4), memo(5), calls
end)
check("varargs3", M.varargs, 1, nil, 3)
check("varargs0", M.varargs)
check("table_unpack_compat", M.table_unpack_compat, { 1, 2, 3 }, 1, 3)

check("Vec", function()
    local Vec = M.Vec
    local p, q = Vec.new(1, 2, 3), Vec.new(4, 5, 6)
    p.w = 5
    return tostring(p + q), tostring(p - q), p * q, tostring(p * 2), tostring(-p), p == q,
        p == Vec.new(1, 2, 3), p < q, p <= q, q < p, p .. q, #p, p.magnitude, p("y"), rawget(p, "w")
end)
check("Proxy", function()
    local inner = { x = 1 }
    local proxy = M.Proxy.wrap(inner)
    proxy.y = 2
    return proxy.x, proxy.y, inner.y, proxy.z, getmetatable(proxy)
end)
check("coroutine_demo", M.coroutine_demo)
check("coroutine_wrap_demo", M.coroutine_wrap_demo)
check("pcall_demo", M.pcall_demo)
check("goto_demo", M.goto_demo, 5)
check("string_lib_demo", M.string_lib_demo)
check("table_lib_demo", M.table_lib_demo)
math.randomseed(42)
check("math_lib_demo", M.math_lib_demo)
check("io_demo", function() return types(M.io_demo()) end)
check("os_demo", function() return types(M.os_demo()) end)
check("ipairs_pairs_demo", M.ipairs_pairs_demo, { 10, 20, x = 1 })
check("setfenv_compat", M.setfenv_compat)
check("require_demo", M.require_demo)
check("rawops_demo", M.rawops_demo, { 1, 2 }, "k", "v")
show("long_table", M.long_table)
check("deep_recursion", M.deep_recursion, 100)
check("pingpong", M.pingpong, 10, 0, 1)
check("long_expression", M.long_expression)
for i, args in ipairs({ { true, false, 1 }, { nil, 2, 3 }, { false, false, false }, { 1, 2, 3 } }) do
    check("logical_short_circuit" .. i, M.logical_short_circuit, args[1], args[2], args[3])
end
check("string_packing_compat", M.string_packing_compat)
check("utf8_lib_compat", M.utf8_lib_compat)
check("bitops_compat", M.bitops_compat)
check("integer_div_compat", M.integer_div_compat)
check("integer_for_5_4", M.integer_for_5_4)
check("to_be_closed_5_4", M.to_be_closed_5_4)
check("const_attrib_5_4", M.const_attrib_5_4)
check("math_tointeger_compat", M.math_tointeger_compat)
check("math_type_compat", M.math_type_compat)
check("debug_lib_demo", function() return types(M.debug_lib_demo()) end)
check("load_string_compat", function()
    local chunk = M.load_string_compat("return 6 * 7")
    local bad, err = M.load_string_compat("return +")
    return chunk(), bad, err
end)
check("pack_unpack_demo", M.pack_unpack_demo)
for n = 0, 21 do check("long_branch_chain" .. n, M.long_branch_chain, n) end
check("nested_loops", M.nested_loops, 3, 4)
check("table_method_chain", M.table_method_chain)
check("Stack", function()
    local s = M.Stack.new()
    s:push(1) s:push(2) s:push(3)
    local popped = s:pop()
    local empty = M.Stack.new()
    return popped, s:peek(), s:size(), empty:pop(), M.method_call_styles(s)
end)
check("Queue", function()
    local q = M.Queue.new()
    q:enqueue("a") q:enqueue("b") q:enqueue("c")
    local first = q:dequeue()
    local empty = M.Queue.new()
    return first, q:dequeue(), q:size(), empty:dequeue(), q.items
end)
check("exception_chain", M.exception_chain)
check("safe_caller", M.safe_caller, function(x, y) return x + y, x - y, x * y end, 5, 3)
check("safe_caller_error", M.safe_caller, error, "raised")
check("string_interp_compat", M.string_interp_compat)
check("table_with_holes", M.table_with_holes)
check("table_remove_during_iter", M.table_remove_during_iter)
check("chained_assignments", M.chained_assignments)
check("string_metatable_demo", M.string_metatable_demo)
check("huge_concat", M.huge_concat)
check("tail_calls", M.tail_calls, 100)
check("multiple_returns", M.multiple_returns)
check("table_constructor_styles", M.table_constructor_styles)
check("string_byte_walk", M.string_byte_walk, "Lua!")
check("format_kitchen_sink", M.format_kitchen_sink)
check("bench_marker", M.bench_marker)
check("deep_clone", function()
    local original = { 1, { 2, 3 }, name = "n" }
    original.self = original
    local copy = M.deep_clone(original)
    return copy, copy.self == copy, copy ~= original, copy[2] ~= original[2]
end)
check("shallow_eq", function()
    return M.shallow_eq({ 1, 2 }, { 1, 2 }), M.shallow_eq({ 1 }, { 1, 2 }), M.shallow_eq(1, "1"),
        M.shallow_eq("x", "x")
end)
check("functional", function()
    local arr = { 1, 2, 3, 4, 5, 6 }
    local even = M.filter(arr, function(v) return v % 2 == 0 end)
    local sq = M.map(arr, function(v) return v * v end)
    local sum = M.reduce(arr, function(acc, v) return acc + v end, 0)
    return even, sq, sum, M.zip(arr, { "a", "b", "c" }), M.take(arr, 2), M.take(arr, 10),
        M.drop(arr, 4), M.drop(arr, 9)
end)
check("combinators", function()
    local add = function(x, y) return x + y end
    local inc = function(x) return x + 1 end
    local dbl = function(x) return x * 2 end
    local count = function(...) return select("#", ...), ... end
    return M.curry(add)(2)(3), M.compose(inc, dbl)(5), M.partial(count, 1, 2)(3, 4),
        M.partial(count)(), M.partial(add, 10)(5)
end)
check("numeric", function()
    local primes = {}
    for n = 0, 40 do if M.is_prime(n) then primes[#primes + 1] = n end end
    return M.fib_iter(0), M.fib_iter(1), M.fib_iter(10), M.fib_iter(30), M.fact_iter(10),
        M.gcd(48, 18), M.lcm(4, 6), primes
end)
check("sorting", function()
    local sorted = M.quicksort({ 5, 2, 9, 1, 5, 6, -3, 0 })
    return sorted, M.binary_search(sorted, 9), M.binary_search(sorted, 4),
        M.binary_search(sorted, -3), M.quicksort({})
end)
check("LinkedList", function()
    local list = M.LinkedList.new()
    list:prepend(1) list:append(2) list:append(3) list:prepend(0)
    local forward = list:to_array()
    return forward, list:reverse():to_array(), list.n
end)
check("Set", function()
    local s = M.Set.new({ 1, 2, 3, 2 })
    local t = M.Set.new({ 3, 4 })
    s:add(5) s:remove(1) s:remove(42)
    return s.members, s.n, s:has(2), s:has(1), s:union(t).members, s:intersect(t).members,
        s:diff(t).members, s:union(t).n
end)
check("event_emitter", function()
    local e = M.event_emitter()
    local seen = {}
    local first = function(v) seen[#seen + 1] = "first" .. v end
    local second = function(v) seen[#seen + 1] = "second" .. v end
    e.on("tick", first)
    e.on("tick", second)
    local n1 = e.emit("tick", 1)
    e.off("tick", first)
    local n2 = e.emit("tick", 2)
    e.off("none", first)
    return n1, n2, e.emit("none"), seen
end)
check("state_machine", function()
    local m = M.state_machine("idle", { idle = { go = "run" }, run = { stop = "idle" } })
    local r1 = m.fire("go")
    local c1 = m.current()
    local r2 = m.fire("jump")
    local r3 = m.fire("stop")
    local empty = M.state_machine("nowhere", {})
    return r1, c1, r2, r3, m.current(), empty.fire("go")
end)
check("lru_cache", function()
    local c = M.lru_cache(2)
    c.set("a", 1) c.set("b", 2)
    local ga = c.get("a")
    c.set("a", 10) c.set("c", 3)
    return ga, c.get("a"), c.get("b"), c.get("c"), c.get("zz"), c.size()
end)
check("trampoline", function()
    local function countdown(n)
        if n == 0 then return "done" end
        return function() return countdown(n - 1) end
    end
    return M.trampoline(countdown, 50), M.trampoline(function(x, y) return x + y end, 2, 3)
end)
check("generators", function()
    return M.generator_take(M.range_gen(1, 10, 3), 10), M.generator_take(M.range_gen(10, 1, -4), 2),
        M.generator_take(M.range_gen(1, 3), 5)
end)
check("string_builder", function()
    local b = M.string_builder()
    b.append("x") b.append("y") b.append("z")
    local joined, plain, size = b.build(","), b.build(), b.size()
    b.clear()
    return joined, plain, size, b.size(), b.build("-")
end)
math.randomseed(42)
check("smoke", M.smoke)
