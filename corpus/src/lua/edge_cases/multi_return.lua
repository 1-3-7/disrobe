local function many()
    return 1, 2, 3, 4, 5
end

local a, b, c = many()
local t = { many() }
local last = select("#", many())
local first, third = select(1, many()), select(3, many())
print(a, b, c, #t, last, first, third)

local function divmod(a, b)
    return a // b, a % b
end

local q, r = divmod(17, 5)
print(q, r)
