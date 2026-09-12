return {
  LuaVersion = "Lua51",
  VarNamePrefix = "",
  NameGenerator = "MangledShuffled",
  PrettyPrint = false,
  Seed = 1337,
  Steps = {
    { Name = "Vmify", Settings = {} },
    {
      Name = "ConstantArray",
      Settings = {
        Threshold = 1,
        StringsOnly = true,
      },
    },
    { Name = "WrapInFunction", Settings = {} },
  },
}
