def classify(n)
  if n > 10
    "big"
  elsif n > 0
    "small"
  else
    "neg"
  end
end

i = 0
total = 0
while i < 5
  total = total + i
  i = i + 1
end
puts classify(total)
puts total
