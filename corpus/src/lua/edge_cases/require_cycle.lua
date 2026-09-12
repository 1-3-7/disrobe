local loaded = package.loaded
local function fake_module(name, value)
    loaded[name] = value
    return value
end

local a = fake_module("disrobe_corpus_a", { name = "A" })
local b = fake_module("disrobe_corpus_b", { name = "B", peer = a })
a.peer = b
print(a.name, a.peer.name, b.peer.peer.name)
