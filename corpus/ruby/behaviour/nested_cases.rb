def deep(v)
  case v
  in [x, *]
    case x
    in Integer then puts "int head #{x}"
    else puts "other head"
    end
  in { k: }
    puts "hash #{k}"
  else
    case v
    in String => s then puts "str #{s}"
    else
      i = 0
      while i < 2
        i += 1
      end
      puts "loop #{i}"
    end
  end
  :done
end
p deep([1]), deep([:a]), deep({ k: 2 }), deep("s"), deep(3.0)
r = [1, 2, 3].map do |e|
  case e
  in 1 then :one
  in Integer if e.even? then :even
  else :odd
  end
end
p r
h = { name: "z", age: 3 }
h => { name: }
puts name
a1 = (1 in Integer)
a2 = ("x" in Integer)
p a1, a2
p([1, 2].sum { |e|
  case e
  in 1 then 10
  else 20
  end
})
def tail(v)
  case v
  in [] then :empty
  in [_, *] then :some
  end
end
p tail([]), tail([1])
