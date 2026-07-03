local function make(name, count)
  local literals = {
    kind = "record",
    tag = 7,
    active = true,
  }
  local mixed = {1, 2, 3, label = name, [10] = count, 4, 5}
  local nested = {
    inner = {a = 1, b = 2},
    list = {"x", "y", "z"},
  }
  return literals, mixed, nested
end
return make
