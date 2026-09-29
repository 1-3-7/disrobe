def grade(v)
  v > 3 ? (v > 4 ? "big" : "mid") : "small"
end
p [grade(5), grade(4), grade(1)]

x = 5
label = x > 3 ? (x > 4 ? "big" : "mid") : "small"
p label

def sign(v) = v.zero? ? :zero : (v.positive? ? :pos : :neg)
p [sign(-2), sign(0), sign(9)]

def bucket(n)
  n < 10 ? (n.even? ? :small_even : :small_odd) : (n < 100 ? :medium : :large)
end
p [3, 4, 50, 500].map { |n| bucket(n) }

flags = [true, false, nil].map { |f| f ? (f == true ? 1 : 2) : 0 }
p flags
