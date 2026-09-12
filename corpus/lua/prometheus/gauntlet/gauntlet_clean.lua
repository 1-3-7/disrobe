local Vector = {}
Vector.__index = Vector

function Vector.new(x, y)
    local self = setmetatable({}, Vector)
    self.x = x
    self.y = y
    return self
end

function Vector:magnitude()
    return math.sqrt(self.x * self.x + self.y * self.y)
end

function Vector:dot(other)
    return self.x * other.x + self.y * other.y
end

function Vector:__tostring()
    return "Vector(" .. tostring(self.x) .. ", " .. tostring(self.y) .. ")"
end

local function range(start, stop, step)
    local result = {}
    local i = start
    while i < stop do
        result[#result + 1] = i
        i = i + step
    end
    return result
end

local function map(tbl, fn)
    local out = {}
    for k, v in ipairs(tbl) do
        out[k] = fn(v)
    end
    return out
end

local function filter(tbl, pred)
    local out = {}
    for _, v in ipairs(tbl) do
        if pred(v) then
            out[#out + 1] = v
        end
    end
    return out
end

local function reduce(tbl, fn, acc)
    for _, v in ipairs(tbl) do
        acc = fn(acc, v)
    end
    return acc
end

local GREETING = "hello from gauntlet"
local SEPARATOR = " | "
local STATUS_OK = "ok"
local STATUS_FAIL = "fail"

local function classify(n)
    if n < 0 then
        return STATUS_FAIL
    elseif n == 0 then
        return "zero"
    else
        return STATUS_OK
    end
end

local nums = range(1, 16, 1)
local evens = filter(nums, function(n) return n % 2 == 0 end)
local squares = map(evens, function(n) return n * n end)
local total = reduce(squares, function(a, b) return a + b end, 0)

local v1 = Vector.new(3, 4)
local v2 = Vector.new(1, 0)
local mag = v1:magnitude()
local dp = v1:dot(v2)

local parts = {
    GREETING,
    classify(total),
    classify(-1),
    classify(0),
    tostring(mag),
    tostring(dp),
    tostring(total),
}
print(table.concat(parts, SEPARATOR))
