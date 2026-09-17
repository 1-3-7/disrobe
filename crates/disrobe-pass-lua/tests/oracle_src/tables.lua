local function build(name, count)
  local t = {}
  t.name = name
  t.count = count
  for i = 1, count do
    t[i] = i * i
  end
  local total = 0
  for _, v in ipairs(t) do
    total = total + v
  end
  return t, total
end
return build
