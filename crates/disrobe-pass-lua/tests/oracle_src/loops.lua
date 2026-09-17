local function sumrange(a, b)
  local total = 0
  for i = a, b do
    total = total + i
  end
  local j = a
  while j < b do
    total = total + j
    j = j + 1
  end
  repeat
    total = total - 1
  until total <= 0
  return total
end
return sumrange
