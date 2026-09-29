
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
