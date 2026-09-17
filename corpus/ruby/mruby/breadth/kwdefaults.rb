def listed(x:, y: [1, 2])
  x + y.length
end

def collected(a, x:, **rest)
  a + x + rest.length
end

def blocked(a, &blk)
  blk.call(a)
end

puts listed(x: 1)
puts collected(1, x: 2, z: 3)
puts blocked(2) { |v| v * 3 }
