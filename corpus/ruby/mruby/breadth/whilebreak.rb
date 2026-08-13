def first_hit(n)
  i = 0
  while i < n
    break if i == 2
    i += 1
  end
  i
end

def inner_scan(n)
  outer = 0
  total = 0
  while outer < n
    inner = 0
    while inner < n
      break if inner == 1
      total += 1
      inner += 1
    end
    outer += 1
  end
  total
end

puts first_hit(9)
puts first_hit(1)
puts inner_scan(3)
