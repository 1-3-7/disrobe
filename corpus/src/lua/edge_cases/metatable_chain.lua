local function chain(level, parent)
    local mt = { __index = parent }
    return setmetatable({ tag = "L" .. level }, mt)
end

local root = { greet = function() return "root-hi" end, depth = 0 }
local l1 = chain(1, root)
local l2 = chain(2, l1)
local l3 = chain(3, l2)
local l4 = chain(4, l3)
local l5 = chain(5, l4)
local l6 = chain(6, l5)

print(l6.tag, l6.greet(), l6.depth)
