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

a, b = 1, 2
a, b = b, a
p [a, b]
c, d, e = 1, 2, 3
c, d, e = e, c, d
p [c, d, e]

record = { name: "x", tags: ["a", "b"] }
case record
in [only]
  p [:array, only]
else
  p :not_an_array
end
p :after_the_case

case record
in { name: String => nm, tags: [first, *] }
  p [nm, first]
end
case [1, { k: 2 }]
in [Integer => i, { k: }]
  p [i, k]
end
