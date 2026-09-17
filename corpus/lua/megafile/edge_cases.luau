--!strict
--[[
edge_cases.luau - Roblox Luau dialect megafile fixture
covers Luau-specific syntax: type annotations, generics, union types,
intersection types, optional types, string interpolation, compound
assignment ops, continue, if-expressions, type declarations, type
aliases, exported types, table type literals, function type literals.
]]

type Vec3 = { x: number, y: number, z: number }
type Maybe<T> = T?
type Either<L, R> = L | R
type Both<A, B> = A & B
type Callback<T...> = (T...) -> ()
type Predicate<T> = (T) -> boolean
type Map<K, V> = { [K]: V }

export type Result<T, E> = { ok: true, value: T } | { ok: false, error: E }
export type Vector = Vec3
export type Point2D = { x: number, y: number }

local module = {}

local function vec(x: number, y: number, z: number): Vec3
    return { x = x, y = y, z = z }
end

local function add_vec(a: Vec3, b: Vec3): Vec3
    return vec(a.x + b.x, a.y + b.y, a.z + b.z)
end

local function dot(a: Vec3, b: Vec3): number
    return a.x * b.x + a.y * b.y + a.z * b.z
end

local function magnitude(v: Vec3): number
    return math.sqrt(dot(v, v))
end

local function normalize(v: Vec3): Vec3
    local m: number = magnitude(v)
    if m == 0 then return vec(0, 0, 0) end
    return vec(v.x / m, v.y / m, v.z / m)
end

module.vec = vec
module.add_vec = add_vec
module.dot = dot
module.magnitude = magnitude
module.normalize = normalize

local function ok<T>(value: T): Result<T, string>
    return { ok = true, value = value }
end

local function err<T>(message: string): Result<T, string>
    return { ok = false, error = message }
end

local function map_result<A, B, E>(r: Result<A, E>, f: (A) -> B): Result<B, E>
    if r.ok then
        return { ok = true, value = f(r.value) }
    end
    return { ok = false, error = r.error }
end

local function unwrap<T, E>(r: Result<T, E>): T
    if r.ok then return r.value end
    error("unwrap on Err")
end

module.ok = ok
module.err = err
module.map_result = map_result
module.unwrap = unwrap

local function compound_ops(): number
    local x: number = 10
    x += 5
    x -= 2
    x *= 3
    x /= 2
    x //= 1
    x %= 100
    x ^= 1
    return x
end

module.compound_ops = compound_ops

local function string_interpolation(name: string, count: number): string
    return `hello, {name} - count={count}`
end

module.string_interpolation = string_interpolation

local function continue_demo(arr: { number }): { number }
    local out: { number } = {}
    for i, v in ipairs(arr) do
        if v % 2 == 0 then continue end
        out[#out + 1] = v
    end
    return out
end

module.continue_demo = continue_demo

local function if_expression(n: number): string
    local label: string = if n < 0 then "neg" elseif n == 0 then "zero" else "pos"
    return label
end

module.if_expression = if_expression

local function generic_fn<T>(arr: { T }, pred: Predicate<T>): { T }
    local out: { T } = {}
    for _, v in ipairs(arr) do
        if pred(v) then
            out[#out + 1] = v
        end
    end
    return out
end

module.generic_fn = generic_fn

local function strict_map<K, V, W>(m: Map<K, V>, f: (V) -> W): Map<K, W>
    local out: Map<K, W> = {}
    for k, v in pairs(m) do out[k] = f(v) end
    return out
end

module.strict_map = strict_map

local function union_arg(x: number | string): string
    if type(x) == "number" then
        return tostring(x * 2)
    end
    return x
end

module.union_arg = union_arg

local function optional_arg(x: number?): number
    return x or 0
end

module.optional_arg = optional_arg

type Player = {
    name: string,
    level: number,
    health: number,
    inventory: { string },
    position: Vec3,
}

local function make_player(name: string, level: number): Player
    return {
        name = name,
        level = level,
        health = 100 + level * 10,
        inventory = {},
        position = vec(0, 0, 0),
    }
end

local function damage(p: Player, amount: number): Player
    p.health -= amount
    return p
end

local function pick_up(p: Player, item: string): Player
    p.inventory[#p.inventory + 1] = item
    return p
end

local function move(p: Player, delta: Vec3): Player
    p.position = add_vec(p.position, delta)
    return p
end

module.make_player = make_player
module.damage = damage
module.pick_up = pick_up
module.move = move

type Event = "spawn" | "death" | "level_up" | "damage" | "heal"
type Handler = (Event, any) -> ()

local function event_bus(): { listen: (Event, Handler) -> (), fire: (Event, any) -> () }
    local handlers: { [Event]: { Handler } } = {}
    local function listen(event: Event, fn: Handler)
        if handlers[event] == nil then handlers[event] = {} end
        local list: { Handler } = handlers[event]
        list[#list + 1] = fn
    end
    local function fire(event: Event, payload: any)
        local list: { Handler }? = handlers[event]
        if list == nil then return end
        for _, fn in ipairs(list) do fn(event, payload) end
    end
    return { listen = listen, fire = fire }
end

module.event_bus = event_bus

local function fold<A, B>(arr: { A }, init: B, f: (B, A) -> B): B
    local acc: B = init
    for _, v in ipairs(arr) do acc = f(acc, v) end
    return acc
end

local function compose<A, B, C>(f: (B) -> C, g: (A) -> B): (A) -> C
    return function(a: A): C return f(g(a)) end
end

module.fold = fold
module.compose = compose

local function table_pack_demo(...): { n: number, [number]: any }
    return table.pack(...)
end

local function table_unpack_demo(t: { n: number, [number]: any }): ...any
    return table.unpack(t, 1, t.n)
end

module.table_pack_demo = table_pack_demo
module.table_unpack_demo = table_unpack_demo

local function buffer_demo()
    if buffer and buffer.create then
        local buf = buffer.create(16)
        buffer.writeu32(buf, 0, 0xCAFEBABE)
        buffer.writei32(buf, 4, -42)
        buffer.writef32(buf, 8, 3.14)
        return {
            u32 = buffer.readu32(buf, 0),
            i32 = buffer.readi32(buf, 4),
            f32 = buffer.readf32(buf, 8),
            len = buffer.len(buf),
        }
    end
    return nil
end

module.buffer_demo = buffer_demo

local function bit32_demo(): { number }
    if bit32 then
        return {
            bit32.band(0xF0, 0x0F),
            bit32.bor(0xF0, 0x0F),
            bit32.bxor(0xF0, 0x0F),
            bit32.bnot(0),
            bit32.lshift(1, 4),
            bit32.rshift(0x100, 4),
        }
    end
    return {}
end

module.bit32_demo = bit32_demo

local function task_compat(): { string }
    if task and task.wait then
        local out: { string } = {}
        out[#out + 1] = "task-available"
        return out
    end
    return { "task-missing" }
end

module.task_compat = task_compat

local function nested_generic<T, U>(arr: { { T } }, f: (T) -> U): { { U } }
    local out: { { U } } = {}
    for i, row in ipairs(arr) do
        local mapped: { U } = {}
        for j, v in ipairs(row) do mapped[j] = f(v) end
        out[i] = mapped
    end
    return out
end

module.nested_generic = nested_generic

local function recursive_type_alias()
    local function build_tree(depth: number, value: number): { value: number, left: any, right: any }
        if depth <= 0 then return { value = value, left = nil, right = nil } end
        return {
            value = value,
            left = build_tree(depth - 1, value * 2),
            right = build_tree(depth - 1, value * 2 + 1),
        }
    end
    return build_tree(3, 1)
end

module.recursive_type_alias = recursive_type_alias

local function string_methods_luau(s: string): { string }
    local out: { string } = {}
    out[#out + 1] = s:upper()
    out[#out + 1] = s:lower()
    out[#out + 1] = s:reverse()
    out[#out + 1] = s:rep(3, "-")
    out[#out + 1] = string.format("len=%d", #s)
    return out
end

module.string_methods_luau = string_methods_luau

local function math_luau(): { number }
    return {
        math.round(3.4),
        math.round(3.6),
        math.clamp(15, 0, 10),
        math.clamp(-5, 0, 10),
        math.sign(-7),
        math.sign(7),
        math.sign(0),
    }
end

module.math_luau = math_luau

local function table_freeze_demo()
    local t = { a = 1, b = 2 }
    if table.freeze then
        table.freeze(t)
        return table.isfrozen and table.isfrozen(t) or true
    end
    return false
end

module.table_freeze_demo = table_freeze_demo

local function table_clone_demo(): { number }
    local src: { number } = { 1, 2, 3, 4, 5 }
    if table.clone then
        return table.clone(src)
    end
    local out: { number } = {}
    for i, v in ipairs(src) do out[i] = v end
    return out
end

module.table_clone_demo = table_clone_demo

local function variadic_typed(...: number): number
    local sum: number = 0
    for _, v in ipairs({...}) do sum = sum + v end
    return sum
end

module.variadic_typed = variadic_typed

local function functional_pipeline(arr: { number }): number
    local doubled: { number } = {}
    for i, v in ipairs(arr) do doubled[i] = v * 2 end
    local positive: { number } = {}
    for _, v in ipairs(doubled) do
        if v > 0 then positive[#positive + 1] = v end
    end
    local sum: number = 0
    for _, v in ipairs(positive) do sum = sum + v end
    return sum
end

module.functional_pipeline = functional_pipeline

type Tree<T> = { value: T, children: { Tree<T> } }

local function tree_size<T>(t: Tree<T>): number
    local n: number = 1
    for _, child in ipairs(t.children) do n = n + tree_size(child) end
    return n
end

local function tree_map<A, B>(t: Tree<A>, f: (A) -> B): Tree<B>
    local mapped_children: { Tree<B> } = {}
    for i, child in ipairs(t.children) do mapped_children[i] = tree_map(child, f) end
    return { value = f(t.value), children = mapped_children }
end

module.tree_size = tree_size
module.tree_map = tree_map

local function smoke(): string
    local p: Player = make_player("Hero", 5)
    p = damage(p, 10)
    p = pick_up(p, "sword")
    p = move(p, vec(1, 0, 0))
    local v: Vec3 = normalize(vec(3, 4, 0))
    local m: number = magnitude(v)
    local r: Result<number, string> = ok(42)
    local r2: Result<string, string> = map_result(r, function(x: number): string return tostring(x) end)
    local s: string = string_interpolation("luau", 7)
    local cont: { number } = continue_demo({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 })
    local sum: number = variadic_typed(1, 2, 3, 4, 5)
    local pipe: number = functional_pipeline({ 1, -2, 3, -4, 5, -6, 7 })
    return `player=${p.name} hp=${p.health} mag=${m} r2_ok=${tostring(r2.ok)} s=${s} cont=${#cont} sum=${sum} pipe=${pipe}`
end

module.smoke = smoke

print("edge_cases.luau loaded")

return module
