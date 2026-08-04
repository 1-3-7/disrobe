local total = 0
for i = 1, 5 do
  if i == 3 then
    total += 100
    continue
  else
    total += i
  end
  total += 10
end
print(total)
