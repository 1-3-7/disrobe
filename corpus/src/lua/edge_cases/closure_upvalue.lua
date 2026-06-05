local function make_counter(start)
    local value = start
    local function increment(delta)
        value = value + (delta or 1)
        return value
    end
    local function reset()
        value = start
        return value
    end
    return increment, reset
end

local inc, reset = make_counter(10)
print(inc(), inc(5), inc(), reset(), inc())
