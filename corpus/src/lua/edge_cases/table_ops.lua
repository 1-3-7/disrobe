local function deep_copy(value)
    if type(value) ~= "table" then return value end
    local out = {}
    for k, v in pairs(value) do
        out[deep_copy(k)] = deep_copy(v)
    end
    return setmetatable(out, getmetatable(value))
end

local src = setmetatable({ a = 1, b = { 2, 3, { 4, 5 } } }, { __index = function() return "fallback" end })
local copy = deep_copy(src)
print(copy.a, copy.b[3][1], copy.unknown)

local tuple = table.pack(1, nil, 3, nil, 5)
print(tuple.n, tuple[1], tuple[3], tuple[5])

local function variadic(...)
    return table.unpack({...}, 1, select("#", ...))
end

print(variadic(10, 20, 30))
