return {
  LuaVersion = "Lua51",
  VarNamePrefix = "",
  NameGenerator = "MangledShuffled",
  PrettyPrint = false,
  Seed = 1337,
  Steps = {
    { Name = "EncryptStrings", Settings = {} },
    {
      Name = "AntiTamper",
      Settings = {
        UseDebug = false,
      },
    },
    { Name = "Vmify", Settings = {} },
    {
      Name = "ConstantArray",
      Settings = {
        Threshold = 1,
        StringsOnly = true,
        Shuffle = true,
        Rotate = true,
        LocalWrapperThreshold = 0,
      },
    },
    { Name = "NumbersToExpressions", Settings = {} },
    { Name = "WrapInFunction", Settings = {} },
  },
}
