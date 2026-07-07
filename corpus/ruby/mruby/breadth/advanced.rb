class Animal
  def initialize(name)
    @name = name
  end

  def speak(sound)
    "#{@name} says #{sound}"
  end
end

class Dog < Animal
  def speak(sound)
    super
  end
end

def twice
  yield 1
  yield 2
end

def greet(name:)
  "hello #{name}"
end

def apply(x:)
  yield x
end

def split_list(list)
  first, *middle, last = list
  [first, middle, last]
end

dog = Dog.new("Rex")
puts dog.speak("woof")

total = 0
twice { |n| total = total + n }
puts total

puts greet(name: "Ada")

puts(apply(x: 5) { |v| v * 2 })

r = split_list([1, 2, 3, 4, 5])
puts r[0]
puts r[1].length
puts r[2]
