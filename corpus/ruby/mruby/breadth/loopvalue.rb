def captured(n)
  i = 0
  got = while i < n
    break i if i == 2
    i += 1
  end
  got.inspect
end

puts captured(9)
puts captured(1)
