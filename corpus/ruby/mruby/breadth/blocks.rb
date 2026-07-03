total = 0
[1, 2, 3, 4].each do |n|
  total = total + n
end
puts total
doubler = lambda { |x| x * 2 }
puts doubler.call(21)
