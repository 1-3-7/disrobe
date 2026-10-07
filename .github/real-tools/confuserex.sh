#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
url="https://github.com/yck1509/ConfuserEx/releases/download/v1.0.0/ConfuserEx_bin.zip"
expected_sha256="${CONFUSEREX_SHA256:-}"

tool="$RUNNER_TEMP/confuserex"
mkdir -p "$tool"
curl --fail --silent --show-error --location --output "$tool/ConfuserEx_bin.zip" "$url"
zip_sha256="$(sha256sum "$tool/ConfuserEx_bin.zip" | cut -d' ' -f1 | tr -d '\')"
if [ -n "$expected_sha256" ] && [ "$zip_sha256" != "$expected_sha256" ]; then
  echo "ConfuserEx_bin.zip sha256 $zip_sha256 does not match the pinned $expected_sha256" >&2
  exit 1
fi
unzip -q "$tool/ConfuserEx_bin.zip" -d "$tool"
cli="$(find "$tool" -name Confuser.CLI.exe | head -n 1)"
test -n "$cli"

cat > "$OUT/tool.env" <<EOF
name=ConfuserEx (yck1509 original)
url=$url
version=ConfuserEx 1.0.0 ConfuserEx_bin.zip sha256 $zip_sha256; Confuser.CLI.exe sha256 $(sha256sum "$cli" | cut -d' ' -f1 | tr -d '\')
runtime=$(dotnet --version) SDK building net48; outputs executed on the Windows runner's .NET Framework
EOF

programs=(
  "GauntletSample:corpus/dotnet/confuserex/gauntlet/GauntletSample.cs"
  "BehaviourSuite:crates/disrobe-pass-dotnet/tests/fixtures/behaviour"
)
presets=(minimum normal aggressive maximum)

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
    cp "$REPO/$source" "$project/"
  fi
  cat > "$project/$program.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net48</TargetFramework>
    <LangVersion>latest</LangVersion>
    <Nullable>disable</Nullable>
    <Optimize>true</Optimize>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <Deterministic>true</Deterministic>
    <PathMap>$(cygpath -w "$project")=/_/</PathMap>
  </PropertyGroup>
</Project>
EOF
  if ! (cd "$project" && MSBUILDDISABLENODEREUSE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0 dotnet build -c Release -p:UseSharedCompilation=false -nologo -v q); then
    printf '%s\t%s\t%s\t%s\n' - "$source" "dotnet build -c Release (net48)" input-failed >> "$OUT/outputs.tsv"
    continue
  fi
  clean="$project/bin/Release/net48/$program.exe"
  cp "$clean" "$OUT/files/$program.clean.exe"
  expected="$(timeout 60 "$clean" 2>&1)" || true
  for preset in "${presets[@]}"; do
    work="$RUNNER_TEMP/$program-$preset"
    mkdir -p "$work/out"
    cat > "$work/$program.crproj" <<EOF
<project outputDir="$(cygpath -w "$work/out")" baseDir="$(cygpath -w "$(dirname "$clean")")" xmlns="http://confuser.codeplex.com">
  <rule pattern="true" preset="$preset" inherit="false" />
  <module path="$program.exe" />
</project>
EOF
    output="files/$program.$preset.exe"
    command="Confuser.CLI.exe -n $program.crproj (preset=$preset, rule pattern=true)"
    if timeout 900 "$cli" -n "$(cygpath -w "$work/$program.crproj")" && test -s "$work/out/$program.exe"; then
      cp "$work/out/$program.exe" "$OUT/$output"
      if actual="$(timeout 60 "$work/out/$program.exe" 2>&1)" && [ "$actual" = "$expected" ]; then
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
