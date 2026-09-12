local source = "key1=val.one; key2=val(two); key3=[bracket]"
for key, val in source:gmatch("(%w+)=([^;]+)") do
    print(key, val)
end

local escaped = string.gsub("a.b.c.d", "%.", "/")
print(escaped)

local quoted = string.match([[say "hello world"]], '"([^"]*)"')
print(quoted)

local balanced = string.match("nested((deep))end", "(%b())")
print(balanced)
