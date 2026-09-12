def double_or_zero(list)
  list.map do |x|
    next 0 if x == 2
    x * 2
  end
end

def find_first_even(list)
  list.each do |x|
    return x if x % 2 == 0
  end
  "none"
end

puts double_or_zero([1, 2, 3]).inspect
puts find_first_even([1, 3, 4, 5]).inspect
puts find_first_even([1, 3, 5]).inspect
