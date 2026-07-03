local function add(a, b)
  return a + b
end
local greeting = "hello from disrobe gauntlet"
local nums = {3, 1, 4, 1, 5, 9, 2, 6}
local total = 0
for _, n in ipairs(nums) do
  total = add(total, n)
end
print(greeting, total)
local function classify(x)
  if x > 30 then return "big" elseif x > 10 then return "medium" else return "small" end
end
print(classify(total))
