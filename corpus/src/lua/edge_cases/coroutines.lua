local function producer(limit)
    for i = 1, limit do
        coroutine.yield(i * i)
    end
    return "done"
end

local co = coroutine.create(producer)
local results = {}
while true do
    local ok, value = coroutine.resume(co, 5)
    if not ok then error(value) end
    results[#results + 1] = value
    if coroutine.status(co) == "dead" then break end
end
print(table.concat(results, ","))
