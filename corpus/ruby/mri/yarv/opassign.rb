cfg = {}
cfg[:cache] ||= {}
cfg[:nested] &&= cfg[:nested].dup
count = 0
count += 1
count -= 2
count *= 3
total = 10
total ||= 5
total &&= 20
hits = {}
hits[:n] += 4
scores = [0, 0]
scores[0] += 7
acc = 0
acc <<= 2
node = Object.new

def node.value
  @value
end

def node.value=(v)
  @value = v
end

node.value ||= 99
node.value += 1
@store ||= []
@store += [1, 2]
$global ||= "x"
matrix = [[1], [2]]
matrix[0][0] += 5
