local function classify(values)
    local out = {}
    for _, v in ipairs(values) do
        if v < 0 then goto skip end
        if v % 2 == 0 then
            out[#out + 1] = "even:" .. v
        else
            out[#out + 1] = "odd:" .. v
        end
        ::skip::
    end
    return out
end

for _, item in ipairs(classify({ 1, -2, 3, -4, 5, 6 })) do
    print(item)
end
