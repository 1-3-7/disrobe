local fruits = {"apple", "banana", "cherry"}
local prices = {apple = 3, banana = 1, cherry = 5}

local function total_price(items, cost)
  local sum = 0
  for _, name in ipairs(items) do
    sum = sum + cost[name]
  end
  return sum
end

local doubled = {}
for index, name in ipairs(fruits) do
  doubled[index] = name .. name
end

print(total_price(fruits, prices), doubled[1], doubled[2], doubled[3], #fruits)
