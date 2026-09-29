def kind(v)
  case v
  in Integer | Float => n if n > 100 then [:big, n]
  in Integer => n then [:int, n]
  in [*, :x, *post] then [:find, post]
  in [*pre, :y, *] then [:find_pre, pre]
  in { type: :pt, x:, y: } then [:pt, x + y]
  in String => s unless s.empty? then [:str, s]
  in nil then :nil
  else :other
  end
end

def classify(v, lim)
  label = :start
  case v
  in ^lim then label = :pinned
  in [Integer => a, [b, *rest]] then label = [:nested, a, b, rest]
  in { name: String => name, tags: [first, *] } then label = [:tagged, name, first]
  in { id: Integer => id, **extra } if extra.empty? then label = [:bare, id]
  in { id: Integer => id, **extra } then label = [:extra, id, extra.keys]
  in 1..9 then label = :digit
  end
  tally = 0
  case lim
  in Integer if lim.odd? then tally += 1
  in Integer then tally += 2
  end
  [label, tally]
end

def pick(v)
  size = case v
         in [] then 0
         in [_] then 1
         in [_, _, *] then :many
         else :none
         end
  word = case v
         in [first, *] if first.is_a?(Symbol) then first.to_s
         else
         end
  [size, word]
end

def route(req)
  case req
  in { method: "GET", path: } then puts "get #{path}"
  in { method: "POST", path:, body: { id: } } then puts "post #{path} #{id}"
  else puts "unknown"
  end
  case req
  in { method: String => m } unless m == "GET" then puts "not get: #{m}"
  in { method: } then puts "method #{method}"
  end
  :routed
end

p kind(500), kind(7), kind([1, :x, 2, 3]), kind([4, 5, :y, 6]), kind({ type: :pt, x: 1, y: 2 })
p kind("hi"), kind(""), kind(nil), kind(2.5)
p classify(3, 3), classify([1, [2, 3, 4]], 5), classify({ name: "n", tags: ["t", "u"] }, 2)
p classify({ id: 7 }, 1), classify({ id: 8, z: 1 }, 4), classify(5, 6)
p pick([]), pick([:a]), pick([:b, 2, 3]), pick("s")
p route({ method: "GET", path: "/a" }), route({ method: "POST", path: "/b", body: { id: 9 } })
p route({ method: "PUT", path: "/c" })
lim = 3
case 3
in ^lim then p :pinned
else p :not_pinned
end
case { a: 1 }
in { a: Integer => a, **rest } then p [a, rest]
end
