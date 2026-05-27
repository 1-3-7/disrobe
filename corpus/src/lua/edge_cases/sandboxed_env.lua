local function run_in_sandbox(code)
    local env = { print = print, math = math }
    local chunk, err = load(code, "sandbox", "t", env)
    if not chunk then return nil, err end
    return chunk()
end

local result = run_in_sandbox("return math.pi * 2")
print(result)

local ok, err = run_in_sandbox("return os.time()")
print(ok, err)
