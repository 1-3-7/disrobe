#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
version="0.45.0"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 MSBUILDDISABLENODEREUSE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0
tools="$RUNNER_TEMP/bitmono-tools"
dotnet tool install --tool-path "$tools" BitMono.GlobalTool --version "$version"
bitmono="$tools/bitmono.console"
package_hash="$(cat "$HOME"/.nuget/packages/bitmono.globaltool/"$version"/*.nupkg.sha512 2>/dev/null || find "$tools" -iname '*.nupkg.sha512' -exec cat {} \; | head -n 1)"

cat > "$OUT/tool.env" <<EOF
name=BitMono
url=https://www.nuget.org/packages/BitMono.GlobalTool/$version
version=BitMono.GlobalTool $version nupkg sha512 (base64) ${package_hash:-unrecorded}
runtime=$(dotnet --version) SDK; outputs executed with the same runtime
EOF

behaviour="$REPO/crates/disrobe-pass-dotnet/tests/fixtures/behaviour"
programs=(
  "GauntletBitMono:corpus/dotnet/obfuscators/bitmono/gauntlet/clean_original.cs"
  "BehaviourSuite:crates/disrobe-pass-dotnet/tests/fixtures/behaviour"
)
presets=(Minimum Normal Maximum)

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for entry in "${programs[@]}"; do
  program="${entry%%:*}"
  source="${entry#*:}"
  project="$RUNNER_TEMP/$program"
  mkdir -p "$project"
  if [ -d "$REPO/$source" ]; then
    cp "$REPO/$source"/*.cs "$project/"
    {
      echo 'internal static class Program'
      echo '{'
      echo '    private static int Main()'
      echo '    {'
      for file in "$REPO/$source"/*.cs; do
        class="$(basename "$file" .cs)"
        echo "        System.Console.WriteLine(\"== $class\");"
        echo "        Behaviour.$class.Run();"
      done
      echo '        return 0;'
      echo '    }'
      echo '}'
    } > "$project/Program.cs"
  else
    cp "$REPO/$source" "$project/$program.cs"
  fi
  cat > "$project/$program.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <Nullable>disable</Nullable>
    <Optimize>true</Optimize>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <Deterministic>true</Deterministic>
    <PathMap>$project=/_/</PathMap>
    <UseSharedCompilation>false</UseSharedCompilation>
  </PropertyGroup>
</Project>
EOF
  if ! (cd "$project" && dotnet build -c Release -nologo -v q); then
    printf '%s\t%s\t%s\t%s\n' - "$source" "dotnet build -c Release (net8.0)" input-failed >> "$OUT/outputs.tsv"
    continue
  fi
  build="$project/bin/Release/net8.0"
  cp "$build/$program.dll" "$OUT/files/$program.clean.dll"
  expected="$(cd "$build" && timeout 60 dotnet "$program.dll" 2>&1)" || true
  for preset in "${presets[@]}"; do
    work="$RUNNER_TEMP/$program-$preset"
    rm -rf "$work"
    mkdir -p "$work"
    cp "$build"/* "$work/"
    output="files/$program.$preset.dll"
    command="bitmono.console -f $program.dll -l . -o out --preset $preset --no-watermark"
    if (cd "$work" && timeout 900 "$bitmono" -f "$program.dll" -l . -o out --preset "$preset" --no-watermark) \
      && produced="$(find "$work/out" -name "$program*.dll" | head -n 1)" && test -n "$produced"; then
      cp "$produced" "$OUT/$output"
      cp "$produced" "$work/$program.dll"
      if actual="$(cd "$work" && timeout 60 dotnet "$program.dll" 2>&1)" && [ "$actual" = "$expected" ]; then
        behaviour=same
      else
        behaviour=differs
        mkdir -p "$OUT/diffs"
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "${actual:-}") > "$OUT/diffs/$program.$preset.txt" || true
      fi
    else
      behaviour=tool-failed
      output=-
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$source" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
