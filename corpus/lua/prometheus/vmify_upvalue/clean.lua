local function make_counter(start)
  local n = start
  local function bump(step)
    n = n + step
    return n
  end
  return bump
end

local c = make_counter(10)
print(c(1))
print(c(2))
print(c(3))
