def first_over(list, limit)
  i = 0
  while i < list.length
    break list[i] if list[i] > limit
    i += 1
  end
end
puts first_over([1, 5, 9, 2], 4).inspect
