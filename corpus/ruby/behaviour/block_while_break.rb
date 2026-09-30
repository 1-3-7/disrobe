def scan(limits)
  seen = []
  limits.each do |limit|
    n = 0
    while n < 10
      n += 1
      break if n >= limit
      seen << n
    end
  end
  seen
end

def first_hits(rows)
  hits = []
  rows.each_with_index do |row, index|
    col = 0
    while col < row.size
      if row[col] == :hit
        hits << [index, col]
        break
      end
      col += 1
    end
  end
  hits
end

p scan([3, 1, 5])
p first_hits([[:miss, :hit, :hit], [:hit], [:miss, :miss]])
