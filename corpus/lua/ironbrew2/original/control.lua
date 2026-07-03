local function classify(n)
  if n < 0 then
    return "negative"
  elseif n == 0 then
    return "zero"
  else
    return "positive"
  end
end

local total = 0
for i = 1, 10 do
  total = total + i
end

local j = 0
while j < 5 do
  j = j + 1
end

print(classify(-3), classify(0), classify(7), total, j)
