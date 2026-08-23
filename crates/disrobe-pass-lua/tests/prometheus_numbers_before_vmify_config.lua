return {
  LuaVersion = "Lua51",
  VarNamePrefix = "",
  NameGenerator = "MangledShuffled",
  PrettyPrint = false,
  Seed = 1337,
  Steps = {
    {
      Name = "NumbersToExpressions",
      Settings = {
        NumberRepresentationMutation = true,
      },
    },
    { Name = "Vmify", Settings = {} },
  },
}
