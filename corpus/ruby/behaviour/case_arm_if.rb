def classify(n, flag)
  out = []
  case n % 4
  when 0
    if n > 10 || flag
      out << "big-or-flag"
    end
  when 1, 2
    out << "small"
  when 3
    unless n < 5 && !flag
      out << "three"
    end
  end
  out << "done"
  out
end

def settle(n, flag)
  out = []
  case n % 3
  when 0
    if n > 10 || flag
    else
      out << "zero-else"
    end
  when 1
    out << "one"
  end
  out << "end"
  out
end

def pick(n, flag)
  out = []
  case n % 3
  when 0
    if n > 10 || flag
      out << "zero-then"
    else
      out << "zero-else"
    end
  when 1, 2
    out << "rest"
  end
  out << "end"
  out
end

[0, 4, 12, 1, 2, 3, 7].each do |n|
  p pick(n, false)
  p pick(n, true)
  p classify(n, false)
  p classify(n, true)
  p settle(n, false)
  p settle(n, true)
end
