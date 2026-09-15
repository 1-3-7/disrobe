local function classify(n)
  if n >= 90 then
    return "A"
  elseif n >= 80 then
    return "B"
  else
    return "F"
  end
end

print(classify(95))
print(classify(85))
print(classify(40))
