def scaled(n)
  i = 0
  until i >= n
    break i * 10 if i == 2
    i += 1
  end
end

def tagged(n)
  i = 0
  while i < n
    break :small if i == 1
    break :big if i == 3
    i += 1
  end
end

puts scaled(5).inspect
puts scaled(1).inspect
puts tagged(9).inspect
puts tagged(1).inspect
