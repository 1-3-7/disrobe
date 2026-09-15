local ffi = require("ffi")
ffi.cdef[[
    typedef struct { int32_t x; int32_t y; } point_t;
    int32_t labs(int32_t v);
]]

local Point = ffi.metatype("point_t", {
    __add = function(a, b) return ffi.new("point_t", a.x + b.x, a.y + b.y) end,
})

local p = Point(3, 4)
local q = Point(1, 2)
local r = p + q
print(r.x, r.y, ffi.C.labs(-9))
