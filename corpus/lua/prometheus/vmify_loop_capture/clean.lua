local fns = {}
local i = 1
while i <= 3 do
  local n = i * 10
  fns[i] = function()
    return n
  end
  i = i + 1
end
print(fns[1]())
print(fns[2]())
print(fns[3]())
